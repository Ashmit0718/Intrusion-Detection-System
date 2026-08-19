"""
Unit tests for detection logic. These don't require root, scapy sniffing,
or real log files - they feed synthetic events straight into the detectors,
which is possible because detection logic is decoupled from packet capture.

Run with: python3 -m pytest tests/ -v
"""

import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.logger import AlertLogger
from nids.detectors import (
    PortScanDetector, SynFloodDetector, IcmpFloodDetector,
    MaliciousPortDetector, ArpSpoofDetector,
)
from hids.log_monitor import SshBruteForceDetector


class CapturingLogger(AlertLogger):
    """Test double that records alerts instead of printing/writing them."""

    def __init__(self):
        self.alerts = []
        # Skip parent __init__ (avoids creating real log files during tests)

    def alert(self, source, rule_name, severity, detail, src_ip=None):
        self.alerts.append({
            "source": source, "rule": rule_name, "severity": severity,
            "detail": detail, "src_ip": src_ip,
        })

    def info(self, message):
        pass


def make_tcp_packet(src_ip, dst_ip, dport, flags="S", t=None):
    return {
        "time": t if t is not None else time.time(),
        "src_ip": src_ip, "dst_ip": dst_ip,
        "proto": "TCP", "sport": 40000, "dport": dport,
        "flags": flags, "icmp_type": None, "arp_src_mac": None,
    }


def make_icmp_packet(src_ip, dst_ip, icmp_type=8, t=None):
    return {
        "time": t if t is not None else time.time(),
        "src_ip": src_ip, "dst_ip": dst_ip,
        "proto": "ICMP", "sport": None, "dport": None,
        "flags": None, "icmp_type": icmp_type, "arp_src_mac": None,
    }


def make_arp_packet(src_ip, mac, t=None):
    return {
        "time": t if t is not None else time.time(),
        "src_ip": src_ip, "dst_ip": None,
        "proto": "ARP", "sport": None, "dport": None,
        "flags": None, "icmp_type": None, "arp_src_mac": mac,
    }


def test_port_scan_triggers_above_threshold():
    logger = CapturingLogger()
    detector = PortScanDetector(logger)
    now = time.time()

    # 20 distinct ports from the same source within the window -> should fire
    for port in range(1, 21):
        detector.process(make_tcp_packet("10.0.0.5", "10.0.0.1", port, t=now))

    assert len(logger.alerts) == 1
    assert logger.alerts[0]["rule"] == "PORT_SCAN"
    assert logger.alerts[0]["src_ip"] == "10.0.0.5"


def test_port_scan_does_not_trigger_below_threshold():
    logger = CapturingLogger()
    detector = PortScanDetector(logger)
    now = time.time()

    for port in range(1, 5):  # only 4 ports, threshold is 15
        detector.process(make_tcp_packet("10.0.0.5", "10.0.0.1", port, t=now))

    assert len(logger.alerts) == 0


def test_syn_flood_triggers():
    logger = CapturingLogger()
    detector = SynFloodDetector(logger)
    now = time.time()

    for _ in range(150):
        detector.process(make_tcp_packet("10.0.0.9", "10.0.0.1", 80, flags="S", t=now))

    assert len(logger.alerts) == 1
    assert logger.alerts[0]["rule"] == "SYN_FLOOD"


def test_syn_flood_ignores_completed_handshakes():
    logger = CapturingLogger()
    detector = SynFloodDetector(logger)
    now = time.time()

    for _ in range(150):
        detector.process(make_tcp_packet("10.0.0.9", "10.0.0.1", 80, flags="SA", t=now))

    assert len(logger.alerts) == 0


def test_icmp_flood_triggers():
    logger = CapturingLogger()
    detector = IcmpFloodDetector(logger)
    now = time.time()

    for _ in range(60):
        detector.process(make_icmp_packet("10.0.0.20", "10.0.0.1", t=now))

    assert len(logger.alerts) == 1
    assert logger.alerts[0]["rule"] == "ICMP_FLOOD"


def test_malicious_port_detector():
    logger = CapturingLogger()
    detector = MaliciousPortDetector(logger)

    detector.process(make_tcp_packet("10.0.0.5", "10.0.0.1", 3389))  # RDP
    detector.process(make_tcp_packet("10.0.0.5", "10.0.0.1", 443))   # benign HTTPS

    assert len(logger.alerts) == 1
    assert logger.alerts[0]["rule"] == "MALICIOUS_PORT"


def test_arp_spoof_detects_mac_change():
    logger = CapturingLogger()
    detector = ArpSpoofDetector(logger)

    detector.process(make_arp_packet("10.0.0.1", "aa:aa:aa:aa:aa:aa"))
    assert len(logger.alerts) == 0  # first sighting, nothing to compare against

    detector.process(make_arp_packet("10.0.0.1", "bb:bb:bb:bb:bb:bb"))
    assert len(logger.alerts) == 1
    assert logger.alerts[0]["rule"] == "ARP_SPOOF"


def test_ssh_bruteforce_triggers():
    logger = CapturingLogger()
    detector = SshBruteForceDetector(logger)
    now = time.time()

    line = "Aug 19 10:00:0{i} host sshd[123]: Failed password for admin from 203.0.113.5 port 5000{i} ssh2"
    for i in range(6):  # threshold is 5
        detector.process_line(line.format(i=i), now=now)

    assert len(logger.alerts) == 1
    assert logger.alerts[0]["rule"] == "SSH_BRUTEFORCE"
    assert logger.alerts[0]["src_ip"] == "203.0.113.5"


def test_ssh_bruteforce_ignores_unrelated_lines():
    logger = CapturingLogger()
    detector = SshBruteForceDetector(logger)

    detector.process_line("Aug 19 10:00:00 host CRON[456]: session opened for user root")
    assert len(logger.alerts) == 0


if __name__ == "__main__":
    # Allow running without pytest installed, e.g. `python3 tests/test_detectors.py`
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__} -> {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
