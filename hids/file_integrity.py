"""
File integrity monitoring: hashes a set of critical files and alerts if
their content, permissions, or existence changes.
"""

import hashlib
import json
import os
import time

from core.logger import Severity


def _hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None


class FileIntegrityMonitor:
    def __init__(self, alert_logger, watched_files, baseline_path="logs/fim_baseline.json"):
        self.log = alert_logger
        self.watched_files = watched_files
        self.baseline_path = baseline_path
        self.baseline = self._load_or_create_baseline()

    def _load_or_create_baseline(self):
        if os.path.exists(self.baseline_path):
            with open(self.baseline_path, "r") as f:
                return json.load(f)

        baseline = {}
        for path in self.watched_files:
            h = _hash_file(path)
            baseline[path] = {"hash": h, "exists": h is not None}
        os.makedirs(os.path.dirname(self.baseline_path) or ".", exist_ok=True)
        with open(self.baseline_path, "w") as f:
            json.dump(baseline, f, indent=2)
        self.log.info(f"FIM baseline created for {len(baseline)} files at {self.baseline_path}")
        return baseline

    def check_once(self):
        """Run a single integrity sweep; call this on a schedule (e.g. every N seconds)."""
        for path in self.watched_files:
            current_hash = _hash_file(path)
            baseline_entry = self.baseline.get(path, {"hash": None, "exists": False})

            existed_before = baseline_entry["exists"]
            exists_now = current_hash is not None

            if existed_before and not exists_now:
                self.log.alert(
                    "HIDS", "FILE_DELETED", Severity.CRITICAL,
                    f"Monitored file was deleted or became unreadable: {path}",
                )
            elif not existed_before and exists_now:
                self.log.alert(
                    "HIDS", "FILE_CREATED", Severity.MEDIUM,
                    f"New file appeared at previously-absent watched path: {path}",
                )
            elif existed_before and exists_now and current_hash != baseline_entry["hash"]:
                self.log.alert(
                    "HIDS", "FILE_MODIFIED", Severity.HIGH,
                    f"Hash mismatch for {path} - content changed since baseline.",
                )

            self.baseline[path] = {"hash": current_hash, "exists": exists_now}

    def run_forever(self, interval_sec=30):
        while True:
            self.check_once()
            time.sleep(interval_sec)
