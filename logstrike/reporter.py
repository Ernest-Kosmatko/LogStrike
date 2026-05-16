"""
LogStrike — Report Generator
Produces JSON, CSV, and rich terminal reports.

Author  : Ernest Kosmatko (@Ernest-Kosmatko)
GitHub  : https://github.com/Ernest-Kosmatko/LogStrike
License : MIT © 2024 Ernest Kosmatko
"""

from __future__ import annotations

import csv
import io
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO

from .analyzer import Finding, LogStrikeAnalyzer
from .rules import Severity

_USE_COLOUR = sys.stdout.isatty()
_RESET = "\033[0m" if _USE_COLOUR else ""
_BOLD  = "\033[1m"  if _USE_COLOUR else ""

_SEV_COLOUR = {
    Severity.INFO:     "\033[36m"  if _USE_COLOUR else "",
    Severity.LOW:      "\033[32m"  if _USE_COLOUR else "",
    Severity.MEDIUM:   "\033[33m"  if _USE_COLOUR else "",
    Severity.HIGH:     "\033[31m"  if _USE_COLOUR else "",
    Severity.CRITICAL: "\033[35m"  if _USE_COLOUR else "",
}

_BANNER = r"""
  _                 ____  _        _ _
 | |    ___   __ _/ ___|| |_ _ __(_) | _____
 | |   / _ \ / _` \___ \| __| '__| | |/ / _ \
 | |__| (_) | (_| |___) | |_| |  | |   <  __/
 |_____\___/ \__, |____/ \__|_|  |_|_|\_\___|
             |___/
   Real-time Log Analysis & Threat Detection
   Author : Ernest Kosmatko (@Ernest-Kosmatko)
   GitHub : https://github.com/Ernest-Kosmatko/LogStrike
"""


def print_banner(file: TextIO = sys.stdout) -> None:
    if _USE_COLOUR:
        print(f"\033[36m{_BANNER}{_RESET}", file=file)
    else:
        print(_BANNER, file=file)


def _sev_badge(sev: Severity) -> str:
    colour = _SEV_COLOUR[sev]
    return f"{_BOLD}{colour}[{sev.value:^8}]{_RESET}"


def print_finding(finding: Finding, file: TextIO = sys.stdout) -> None:
    f = finding
    ts = f.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if f.entry.timestamp else "??:??:??"
    ip = f.entry.ip or "?"
    user = f.entry.user or "-"
    badge = _sev_badge(f.rule.severity)

    print(f"{badge} {_BOLD}{f.rule.id}{_RESET} {f.rule.name}", file=file)
    print(f"  ⏱  {ts}  |  IP: {ip}  |  User: {user}", file=file)
    print(f"  📋 {f.rule.mitre_tactic} → {f.rule.mitre_technique}", file=file)
    print(f"  🔗 {f.rule.mitre_url}", file=file)
    msg = (f.entry.message[:120] + "…") if len(f.entry.message) > 120 else f.entry.message
    print(f"  ✏  {msg}", file=file)
    print(file=file)


def print_summary(analyzer: LogStrikeAnalyzer, file: TextIO = sys.stdout) -> None:
    s = analyzer.summary()
    sep = "─" * 62

    print(f"\n{_BOLD}{'═' * 62}{_RESET}", file=file)
    print(f"{_BOLD}  LogStrike — Analysis Summary{_RESET}", file=file)
    print(f"  Author    : Ernest Kosmatko (@Ernest-Kosmatko)", file=file)
    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", file=file)
    print(sep, file=file)
    print(f"  Lines processed : {s['total_lines_processed']:,}", file=file)
    print(f"  Total findings  : {s['total_findings']:,}", file=file)

    print(f"\n{_BOLD}  Findings by Severity{_RESET}", file=file)
    for sev in reversed(Severity):
        count = s["findings_by_severity"].get(sev.value, 0)
        bar = "█" * min(count, 40)
        badge = _sev_badge(sev)
        print(f"  {badge}  {bar} {count}", file=file)

    if s["findings_by_tactic"]:
        print(f"\n{_BOLD}  MITRE ATT&CK Tactics Triggered{_RESET}", file=file)
        for tactic, count in sorted(s["findings_by_tactic"].items(), key=lambda x: -x[1]):
            print(f"  {count:4d}  {tactic}", file=file)

    if s["top_offending_ips"]:
        print(f"\n{_BOLD}  Top Offending IPs{_RESET}", file=file)
        for entry in s["top_offending_ips"][:10]:
            print(f"  {entry['count']:4d}  {entry['ip']}", file=file)

    if s["brute_force_sources"]:
        print(f"\n{_BOLD}  Brute-Force Campaigns (≥ threshold){_RESET}", file=file)
        for ip, info in s["brute_force_sources"].items():
            first = info["first_seen"].strftime("%H:%M:%S") if info["first_seen"] else "?"
            print(f"  {ip:<18} {info['failures']:4d} failures  first@{first}", file=file)

    print(f"{_BOLD}{'═' * 62}{_RESET}\n", file=file)


def to_json(analyzer: LogStrikeAnalyzer, indent: int = 2) -> str:
    payload = {
        "tool": "LogStrike",
        "author": "Ernest Kosmatko (@Ernest-Kosmatko)",
        "github": "https://github.com/Ernest-Kosmatko/LogStrike",
        "license": "MIT © 2024 Ernest Kosmatko",
        "generated_at": datetime.now().isoformat(),
        "summary": analyzer.summary(),
        "findings": [f.to_dict() for f in analyzer.findings],
    }
    return json.dumps(payload, indent=indent, default=str)


def save_json(analyzer: LogStrikeAnalyzer, path: str | Path) -> None:
    with open(path, "w") as fh:
        fh.write(to_json(analyzer))


_CSV_FIELDS = [
    "rule_id", "rule_name", "severity", "mitre_tactic", "mitre_technique",
    "log_source", "timestamp", "ip", "user", "message",
]


def to_csv(analyzer: LogStrikeAnalyzer) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for f in analyzer.findings:
        writer.writerow(f.to_dict())
    return buf.getvalue()


def save_csv(analyzer: LogStrikeAnalyzer, path: str | Path) -> None:
    with open(path, "w", newline="") as fh:
        fh.write(to_csv(analyzer))
