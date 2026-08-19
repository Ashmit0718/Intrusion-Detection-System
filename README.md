# Hybrid Intrusion Detection System (NIDS + HIDS)

A signature-based intrusion detection system combining network traffic
analysis with host-level monitoring. Built as a portfolio project to
demonstrate detection engineering: turning known attack patterns into
concrete, testable detection rules.

## What it detects

**Network (NIDS)** — live packet capture via `scapy`
| Signature | What it catches |
|---|---|
| `PORT_SCAN` | One source IP touching many distinct ports quickly (nmap-style recon) |
| `SYN_FLOOD` | Volume of SYN packets to one destination with no completed handshake |
| `ICMP_FLOOD` | Ping-flood style ICMP echo bursts from one source |
| `MALICIOUS_PORT` | Traffic on ports associated with known malware/backdoors (4444, 31337, etc.) |
| `ARP_SPOOF` | A known IP suddenly claiming a different MAC address (MITM indicator) |

**Host (HIDS)**
| Signature | What it catches |
|---|---|
| `SSH_BRUTEFORCE` | Repeated failed SSH logins from one IP within a time window |
| `SUCCESSFUL_LOGIN_AFTER_FAILURES` | A login that succeeds right after a burst of failures |
| `FILE_MODIFIED` / `FILE_DELETED` / `FILE_CREATED` | SHA-256 drift on critical files (`/etc/passwd`, `sshd_config`, etc.) |
| `SUSPICIOUS_PROCESS` | Running processes matching known offensive tooling (netcat, mimikatz, hydra, ...) |

## Architecture

```
main.py                 orchestrates everything, one thread per monitor
core/logger.py           single alert pipeline -> colored console + log file
nids/
  signatures.py          rule data: bad ports, thresholds
  detectors.py            stateful detection logic (pure, no scapy dependency)
  sniffer.py              scapy capture -> normalizes packets -> feeds detectors
hids/
  signatures.py           regex patterns, suspicious process names, watched files
  log_monitor.py          tails auth.log, feeds lines to SSH brute-force detector
  file_integrity.py       SHA-256 baseline + periodic re-check
  process_monitor.py      periodic psutil scan against signature list
tests/test_detectors.py  unit tests using synthetic packets/log lines (no root needed)
```

The key design choice: **detection logic never touches scapy or the filesystem
directly**. `PortScanDetector.process()` takes a plain dict, not a scapy packet;
`SshBruteForceDetector.process_line()` takes a string, not a live file handle.
That's what makes the whole rule engine unit-testable without root privileges
or a live network — see `tests/test_detectors.py`, which exercises every
signature with synthetic attack traffic and asserts the exact alert fires.

## Running it

```bash
pip install -r requirements.txt

# Full system (needs root for packet capture)
sudo python3 main.py

# Host-only mode, no root required
python3 main.py --no-nids

# Run the test suite
python3 -m pytest tests/ -v
```

Edit `config.yaml` to point `hids.auth_log_path` at your system's SSH log
(`/var/log/auth.log` on Debian/Ubuntu, `/var/log/secure` on RHEL/CentOS) and
adjust `hids.watched_files` to paths you actually want integrity-checked.
Detection thresholds (scan sensitivity, flood counts, time windows) live in
`nids/signatures.py`.

## Design notes / trade-offs

- **Signature-based, not ML/anomaly-based.** Chose this deliberately for
  transparency: every alert traces back to a named, human-readable rule
  instead of a model score. Trade-off is it can't catch novel attack
  patterns outside the signature set — a natural "v2" extension would be
  a baseline-traffic anomaly detector alongside these rules.
- **In-memory sliding windows** (`collections.deque`) for rate-based rules
  (port scan, SYN/ICMP flood, brute force) rather than a database — keeps
  the system dependency-free and fast, at the cost of losing state on
  restart.
- **De-duplication per time bucket** so a sustained attack logs one alert
  per window instead of flooding the log file with repeats of the same
  finding.

## Possible extensions

- Anomaly detection layer (baseline normal traffic volume, flag deviations)
- Slack/email alerting for CRITICAL severity events
- Web dashboard for alert history (the alert log is structured enough to
  parse directly)
- GeoIP lookup on source IPs in alerts
