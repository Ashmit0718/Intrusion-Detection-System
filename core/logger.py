"""
Unified alert logger for the IDS.

Every detector (NIDS or HIDS) raises alerts through this single module so
that output format, severity coloring, and log persistence stay consistent
across the whole system.
"""

import logging
import os
from datetime import datetime, timezone
from enum import Enum


class Severity(Enum):
    LOW = ("LOW", "\033[94m")       # blue
    MEDIUM = ("MEDIUM", "\033[93m")  # yellow
    HIGH = ("HIGH", "\033[91m")      # red
    CRITICAL = ("CRITICAL", "\033[95m")  # magenta

    @property
    def label(self):
        return self.value[0]

    @property
    def color(self):
        return self.value[1]


RESET = "\033[0m"


class AlertLogger:
    """Writes alerts to console (colorized) and to a persistent log file."""

    def __init__(self, log_path="logs/ids_alerts.log"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

        self._file_logger = logging.getLogger("ids_file")
        self._file_logger.setLevel(logging.INFO)
        # Avoid duplicate handlers if instantiated more than once
        if not self._file_logger.handlers:
            handler = logging.FileHandler(log_path)
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            self._file_logger.addHandler(handler)

    def alert(self, source, rule_name, severity: Severity, detail, src_ip=None):
        """
        source: 'NIDS' or 'HIDS'
        rule_name: short id of the signature/rule that fired, e.g. 'PORT_SCAN'
        severity: Severity enum
        detail: human readable description
        src_ip: originating IP/host if applicable
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        ip_part = f" src={src_ip}" if src_ip else ""

        plain_line = f"[{timestamp}] [{source}] [{severity.label}] [{rule_name}]{ip_part} {detail}"
        colored_line = (
            f"{severity.color}[{timestamp}] [{source}] [{severity.label}] "
            f"[{rule_name}]{ip_part} {detail}{RESET}"
        )

        print(colored_line)
        self._file_logger.info(plain_line)

    def info(self, message):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        line = f"[{timestamp}] [SYSTEM] {message}"
        print(line)
        self._file_logger.info(line)
