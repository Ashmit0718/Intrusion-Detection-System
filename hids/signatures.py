"""
Signature/rule definitions for the host-based detector.
"""

import re

# Regex patterns matched against auth log lines (OpenSSH format on Linux).
SSH_FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
SSH_ACCEPTED_LOGIN_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)"
)

# Process names that are rarely legitimate on a normal workstation/server
# and are commonly used for reconnaissance, tunneling, or post-exploitation.
SUSPICIOUS_PROCESS_NAMES = {
    "nc": "netcat - often used for reverse shells / data exfiltration",
    "ncat": "netcat variant - reverse shells / tunneling",
    "socat": "relay tool commonly abused for pivoting",
    "mimikatz": "credential dumping tool",
    "john": "password cracker (John the Ripper)",
    "hydra": "network login brute-forcer",
    "nmap": "network scanner - suspicious if run unexpectedly on a host",
    "tcpdump": "packet capture - suspicious if run by non-admin unexpectedly",
}

# Files considered critical enough to hash and monitor for tampering.
# Adjust this list to match real paths on the deployment host.
DEFAULT_WATCHED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
]
