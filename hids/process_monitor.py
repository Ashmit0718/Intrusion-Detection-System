"""
Process monitoring: periodically scans running processes for names that
match known-suspicious tooling (see hids/signatures.py).
"""

import time

from core.logger import Severity
from hids.signatures import SUSPICIOUS_PROCESS_NAMES

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class ProcessMonitor:
    def __init__(self, alert_logger):
        self.log = alert_logger
        self._already_alerted_pids = set()

    def check_once(self):
        if not PSUTIL_AVAILABLE:
            self.log.info("psutil not installed - process monitoring disabled. "
                           "Install with: pip install psutil")
            return

        for proc in psutil.process_iter(["pid", "name", "username", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            # Match on whole tokens (split on common separators) rather than
            # raw substring, so e.g. "sync_wq" doesn't falsely match "nc".
            name_tokens = set(name.replace("-", " ").replace("_", " ").replace("/", " ").split())
            for suspicious_name, reason in SUSPICIOUS_PROCESS_NAMES.items():
                is_match = suspicious_name in name_tokens or name == suspicious_name
                if is_match and proc.info["pid"] not in self._already_alerted_pids:
                    self._already_alerted_pids.add(proc.info["pid"])
                    cmdline = " ".join(proc.info.get("cmdline") or [])
                    self.log.alert(
                        "HIDS", "SUSPICIOUS_PROCESS", Severity.MEDIUM,
                        f"Process '{name}' (pid {proc.info['pid']}, user "
                        f"{proc.info.get('username')}) matched signature: {reason}. "
                        f"cmdline: {cmdline}",
                    )

    def run_forever(self, interval_sec=15):
        while True:
            self.check_once()
            time.sleep(interval_sec)
