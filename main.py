"""
Entry point for the hybrid IDS. Starts the network sniffer and the host
monitors (log tailing, file integrity, process scanning) each in their own
thread, all reporting through one shared AlertLogger.

Usage:
    sudo python3 main.py                  # needs root for live packet capture
    python3 main.py --no-nids             # run host-only, no root needed
"""

import argparse
import sys
import threading

import yaml

from core.logger import AlertLogger
from nids.detectors import NidsEngine
from nids.sniffer import start_sniffing
from hids.log_monitor import SshBruteForceDetector, monitor_auth_log
from hids.file_integrity import FileIntegrityMonitor
from hids.process_monitor import ProcessMonitor


def load_config(path="config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Hybrid Network + Host Intrusion Detection System")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--no-nids", action="store_true", help="disable network sniffing (no root needed)")
    parser.add_argument("--no-hids", action="store_true", help="disable host monitoring")
    args = parser.parse_args()

    config = load_config(args.config)
    alert_logger = AlertLogger(log_path=config["logging"]["log_path"])
    alert_logger.info("IDS starting up.")

    threads = []

    if config["nids"]["enabled"] and not args.no_nids:
        engine = NidsEngine(alert_logger)
        t = threading.Thread(
            target=start_sniffing,
            kwargs={
                "engine": engine,
                "alert_logger": alert_logger,
                "iface": config["nids"]["interface"],
                "bpf_filter": config["nids"]["bpf_filter"],
            },
            daemon=True,
        )
        threads.append(t)
    else:
        alert_logger.info("NIDS disabled.")

    if config["hids"]["enabled"] and not args.no_hids:
        ssh_detector = SshBruteForceDetector(alert_logger)
        t_log = threading.Thread(
            target=monitor_auth_log,
            args=(config["hids"]["auth_log_path"], ssh_detector, alert_logger),
            daemon=True,
        )
        threads.append(t_log)

        fim = FileIntegrityMonitor(alert_logger, config["hids"]["watched_files"])
        t_fim = threading.Thread(
            target=fim.run_forever,
            args=(config["hids"]["file_integrity_interval_sec"],),
            daemon=True,
        )
        threads.append(t_fim)

        proc_mon = ProcessMonitor(alert_logger)
        t_proc = threading.Thread(
            target=proc_mon.run_forever,
            args=(config["hids"]["process_scan_interval_sec"],),
            daemon=True,
        )
        threads.append(t_proc)
    else:
        alert_logger.info("HIDS disabled.")

    if not threads:
        alert_logger.info("Both NIDS and HIDS disabled - nothing to run.")
        sys.exit(1)

    for t in threads:
        t.start()

    alert_logger.info(f"IDS running with {len(threads)} monitor thread(s). Press Ctrl+C to stop.")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        alert_logger.info("IDS shutting down.")


if __name__ == "__main__":
    main()
