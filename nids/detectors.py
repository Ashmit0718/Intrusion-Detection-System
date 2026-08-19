"""
Stateful network detectors.

Each detector consumes normalized packet-info dicts (not raw scapy packets)
so the logic can be unit tested without needing root/live traffic:

    {
        "time": float (unix timestamp),
        "src_ip": str,
        "dst_ip": str,
        "proto": "TCP" | "UDP" | "ICMP" | "ARP",
        "sport": int or None,
        "dport": int or None,
        "flags": str or None,   # e.g. "S", "SA", "A" for TCP
        "icmp_type": int or None,
        "arp_src_mac": str or None,
    }
"""

import time
from collections import defaultdict, deque

from core.logger import Severity
from nids.signatures import KNOWN_MALICIOUS_PORTS, THRESHOLDS, RULE_DESCRIPTIONS


class PortScanDetector:
    """Flags a source IP that touches many distinct ports in a short window."""

    def __init__(self, alert_logger):
        self.log = alert_logger
        self.window = THRESHOLDS["port_scan_window_sec"]
        self.threshold = THRESHOLDS["port_scan_unique_ports"]
        # src_ip -> deque[(timestamp, port)]
        self._history = defaultdict(deque)
        self._already_alerted = set()

    def process(self, pkt):
        if pkt["proto"] != "TCP" or pkt["dport"] is None:
            return
        src, now, port = pkt["src_ip"], pkt["time"], pkt["dport"]
        dq = self._history[src]
        dq.append((now, port))

        while dq and now - dq[0][0] > self.window:
            dq.popleft()

        unique_ports = {p for _, p in dq}
        if len(unique_ports) >= self.threshold:
            key = (src, now // self.window)
            if key not in self._already_alerted:
                self._already_alerted.add(key)
                self.log.alert(
                    "NIDS", "PORT_SCAN", Severity.HIGH,
                    f"{len(unique_ports)} distinct ports probed in {self.window}s. "
                    f"{RULE_DESCRIPTIONS['PORT_SCAN']}",
                    src_ip=src,
                )


class SynFloodDetector:
    """Flags excessive SYN (no ACK) packets aimed at one destination."""

    def __init__(self, alert_logger):
        self.log = alert_logger
        self.window = THRESHOLDS["syn_flood_window_sec"]
        self.threshold = THRESHOLDS["syn_flood_count"]
        self._history = defaultdict(deque)
        self._already_alerted = set()

    def process(self, pkt):
        if pkt["proto"] != "TCP" or pkt["flags"] != "S":
            return
        dst, now = pkt["dst_ip"], pkt["time"]
        dq = self._history[dst]
        dq.append(now)

        while dq and now - dq[0] > self.window:
            dq.popleft()

        if len(dq) >= self.threshold:
            key = (dst, now // self.window)
            if key not in self._already_alerted:
                self._already_alerted.add(key)
                self.log.alert(
                    "NIDS", "SYN_FLOOD", Severity.CRITICAL,
                    f"{len(dq)} SYN packets in {self.window}s with no completed handshake. "
                    f"{RULE_DESCRIPTIONS['SYN_FLOOD']}",
                    src_ip=pkt["src_ip"],
                )


class IcmpFloodDetector:
    """Flags excessive ICMP echo requests from a single source."""

    def __init__(self, alert_logger):
        self.log = alert_logger
        self.window = THRESHOLDS["icmp_flood_window_sec"]
        self.threshold = THRESHOLDS["icmp_flood_count"]
        self._history = defaultdict(deque)
        self._already_alerted = set()

    def process(self, pkt):
        if pkt["proto"] != "ICMP" or pkt["icmp_type"] != 8:  # 8 = echo request
            return
        src, now = pkt["src_ip"], pkt["time"]
        dq = self._history[src]
        dq.append(now)

        while dq and now - dq[0] > self.window:
            dq.popleft()

        if len(dq) >= self.threshold:
            key = (src, now // self.window)
            if key not in self._already_alerted:
                self._already_alerted.add(key)
                self.log.alert(
                    "NIDS", "ICMP_FLOOD", Severity.MEDIUM,
                    f"{len(dq)} ICMP echo requests in {self.window}s. "
                    f"{RULE_DESCRIPTIONS['ICMP_FLOOD']}",
                    src_ip=src,
                )


class MaliciousPortDetector:
    """Flags any traffic touching a port on the known-bad-port list."""

    def __init__(self, alert_logger):
        self.log = alert_logger
        self._already_alerted = set()

    def process(self, pkt):
        for port_field in ("sport", "dport"):
            port = pkt.get(port_field)
            if port in KNOWN_MALICIOUS_PORTS:
                key = (pkt["src_ip"], pkt["dst_ip"], port)
                if key not in self._already_alerted:
                    self._already_alerted.add(key)
                    self.log.alert(
                        "NIDS", "MALICIOUS_PORT", Severity.HIGH,
                        f"Traffic on port {port} ({KNOWN_MALICIOUS_PORTS[port]}) "
                        f"between {pkt['src_ip']} and {pkt['dst_ip']}.",
                        src_ip=pkt["src_ip"],
                    )


class ArpSpoofDetector:
    """Flags when a known IP suddenly maps to a different MAC address."""

    def __init__(self, alert_logger):
        self.log = alert_logger
        self._ip_to_mac = {}

    def process(self, pkt):
        if pkt["proto"] != "ARP" or not pkt.get("arp_src_mac"):
            return
        ip, mac = pkt["src_ip"], pkt["arp_src_mac"]
        known_mac = self._ip_to_mac.get(ip)
        if known_mac and known_mac != mac:
            self.log.alert(
                "NIDS", "ARP_SPOOF", Severity.CRITICAL,
                f"{ip} was {known_mac}, now claims to be {mac}. "
                f"{RULE_DESCRIPTIONS['ARP_SPOOF']}",
                src_ip=ip,
            )
        self._ip_to_mac[ip] = mac


class NidsEngine:
    """Fan-out wrapper: feeds each normalized packet to all active detectors."""

    def __init__(self, alert_logger):
        self.detectors = [
            PortScanDetector(alert_logger),
            SynFloodDetector(alert_logger),
            IcmpFloodDetector(alert_logger),
            MaliciousPortDetector(alert_logger),
            ArpSpoofDetector(alert_logger),
        ]

    def process_packet(self, pkt_info):
        for detector in self.detectors:
            detector.process(pkt_info)
