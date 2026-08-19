"""
Host log monitoring - tails an auth log and detects brute-force SSH login
attempts. Detection logic is separated from file-tailing so it can be unit
tested by just feeding it lines directly.
"""

import os
import time
from collections import defaultdict, deque

from core.logger import Severity
from hids.signatures import SSH_FAILED_LOGIN_PATTERN, SSH_ACCEPTED_LOGIN_PATTERN
from nids.signatures import THRESHOLDS


class SshBruteForceDetector:
    """Flags an IP with too many failed SSH logins in a short window."""

    def __init__(self, alert_logger):
        self.log = alert_logger
        self.window = THRESHOLDS["ssh_bruteforce_window_sec"]
        self.threshold = THRESHOLDS["ssh_bruteforce_attempts"]
        self._history = defaultdict(deque)
        self._already_alerted = set()

    def process_line(self, line, now=None):
        now = now if now is not None else time.time()

        match = SSH_FAILED_LOGIN_PATTERN.search(line)
        if match:
            ip = match.group("ip")
            user = match.group("user")
            dq = self._history[ip]
            dq.append(now)
            while dq and now - dq[0] > self.window:
                dq.popleft()

            if len(dq) >= self.threshold:
                key = (ip, now // self.window)
                if key not in self._already_alerted:
                    self._already_alerted.add(key)
                    self.log.alert(
                        "HIDS", "SSH_BRUTEFORCE", Severity.HIGH,
                        f"{len(dq)} failed SSH login attempts in {self.window}s "
                        f"(most recent target user: '{user}').",
                        src_ip=ip,
                    )
            return

        match = SSH_ACCEPTED_LOGIN_PATTERN.search(line)
        if match:
            ip = match.group("ip")
            # A successful login right after a burst of failures is notable -
            # it suggests the brute force may have worked.
            recent_failures = len(self._history.get(ip, []))
            if recent_failures >= self.threshold // 2:
                self.log.alert(
                    "HIDS", "SUCCESSFUL_LOGIN_AFTER_FAILURES", Severity.CRITICAL,
                    f"Successful SSH login from {ip} for user "
                    f"'{match.group('user')}' after {recent_failures} recent failures.",
                    src_ip=ip,
                )


def tail_file(path, from_end=True):
    """Generator that yields new lines appended to a file, like `tail -f`."""
    with open(path, "r") as f:
        if from_end:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def monitor_auth_log(path, detector: SshBruteForceDetector, alert_logger, from_end=True):
    if not os.path.exists(path):
        alert_logger.info(f"HIDS log monitor: '{path}' not found, skipping.")
        return
    alert_logger.info(f"HIDS log monitor watching {path}")
    for line in tail_file(path, from_end=from_end):
        detector.process_line(line)
