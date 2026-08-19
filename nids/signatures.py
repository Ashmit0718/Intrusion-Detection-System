"""
Signature/rule definitions for the network-based detector.

Keeping rules as plain data (not buried in detection logic) means new
signatures can be added by editing this file only.
"""

# Ports commonly associated with malware C2, known vulnerable services,
# or services that should never be exposed on this host's network.
KNOWN_MALICIOUS_PORTS = {
    23: "Telnet (often targeted by IoT botnets)",
    135: "MS RPC (historically exploited - Blaster, etc.)",
    445: "SMB (EternalBlue / ransomware propagation)",
    3389: "RDP (common brute-force / ransomware entry point)",
    4444: "Common default Metasploit handler port",
    31337: "Classic backdoor / Back Orifice port",
    6667: "IRC (legacy botnet C2 channel)",
}

# Detection thresholds - tune these based on your environment's normal traffic
THRESHOLDS = {
    "port_scan_unique_ports": 15,     # distinct ports from one src IP
    "port_scan_window_sec": 10,       # ...within this many seconds
    "syn_flood_count": 100,           # SYN packets to one dst
    "syn_flood_window_sec": 5,
    "icmp_flood_count": 50,           # ICMP echo requests from one src
    "icmp_flood_window_sec": 5,
    "ssh_bruteforce_attempts": 5,     # failed SSH logins (HIDS side)
    "ssh_bruteforce_window_sec": 60,
}

RULE_DESCRIPTIONS = {
    "PORT_SCAN": "Source IP touched an unusually high number of distinct ports in a short window - classic reconnaissance behavior (e.g. nmap).",
    "SYN_FLOOD": "High volume of TCP SYN packets to a single destination without completed handshakes - possible DoS.",
    "ICMP_FLOOD": "High volume of ICMP echo requests from a single source - possible ping flood / DoS.",
    "MALICIOUS_PORT": "Traffic observed on a port associated with known malware or high-risk services.",
    "ARP_SPOOF": "Conflicting MAC address observed for a known IP - possible ARP cache poisoning / MITM.",
}
