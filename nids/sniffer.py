"""
Live packet capture, using scapy. Requires root/administrator privileges
and a real network interface, so this module is only exercised at runtime
(not in unit tests - see tests/test_detectors.py for logic-only tests).
"""

import time

try:
    from scapy.all import sniff, TCP, UDP, ICMP, ARP, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def normalize_packet(pkt):
    """Convert a raw scapy packet into the plain dict our detectors expect."""
    info = {
        "time": time.time(),
        "src_ip": None,
        "dst_ip": None,
        "proto": None,
        "sport": None,
        "dport": None,
        "flags": None,
        "icmp_type": None,
        "arp_src_mac": None,
    }

    if pkt.haslayer(ARP):
        info["proto"] = "ARP"
        info["src_ip"] = pkt[ARP].psrc
        info["arp_src_mac"] = pkt[ARP].hwsrc
        return info

    if not pkt.haslayer(IP):
        return None  # not something we track (e.g. non-IP L2 traffic)

    info["src_ip"] = pkt[IP].src
    info["dst_ip"] = pkt[IP].dst

    if pkt.haslayer(TCP):
        info["proto"] = "TCP"
        info["sport"] = pkt[TCP].sport
        info["dport"] = pkt[TCP].dport
        flags = pkt[TCP].flags
        # Map scapy's flag bits to a short string; we only care about a few
        flag_str = ""
        if flags & 0x02:
            flag_str += "S"
        if flags & 0x10:
            flag_str += "A"
        if flags & 0x01:
            flag_str += "F"
        if flags & 0x04:
            flag_str += "R"
        info["flags"] = flag_str
    elif pkt.haslayer(UDP):
        info["proto"] = "UDP"
        info["sport"] = pkt[UDP].sport
        info["dport"] = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        info["proto"] = "ICMP"
        info["icmp_type"] = int(pkt[ICMP].type)
    else:
        return None

    return info


def start_sniffing(engine, alert_logger, iface=None, bpf_filter=None):
    """
    Blocking call: sniffs packets on `iface` (or scapy's default) and feeds
    each normalized packet into the NIDS engine.
    """
    if not SCAPY_AVAILABLE:
        alert_logger.info(
            "scapy is not installed - NIDS live capture disabled. "
            "Install with: pip install scapy"
        )
        return

    alert_logger.info(f"NIDS sniffer starting on iface={iface or 'default'}")

    def _handle(pkt):
        info = normalize_packet(pkt)
        if info:
            engine.process_packet(info)

    sniff(iface=iface, filter=bpf_filter, prn=_handle, store=False)
