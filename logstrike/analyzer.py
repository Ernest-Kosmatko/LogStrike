"""
LogStrike — Core Analyzer
Correlates log entries against detection rules and tracks statistical anomalies.

Author  : Ernest Kosmatko (@Ernest-Kosmatko)
GitHub  : https://github.com/Ernest-Kosmatko/LogStrike
License : MIT © 2024 Ernest Kosmatko
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .parser import LogEntry, parse_file, parse_line
from .rules import RULES, Severity, ThreatRule


@dataclass
class Finding:
    rule: ThreatRule
    entry: LogEntry
    detected_at: datetime = field(default_factory=datetime.now)

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "rule_name": self.rule.name,
            "severity": self.rule.severity.value,
            "mitre_tactic": self.rule.mitre_tactic,
            "mitre_technique": self.rule.mitre_technique,
            "mitre_url": self.rule.mitre_url,
            "tags": self.rule.tags,
            "log_source": self.entry.source.value,
            "timestamp": self.entry.timestamp.isoformat() if self.entry.timestamp else None,
            "ip": self.entry.ip,
            "user": self.entry.user,
            "message": self.entry.message,
            "raw": self.entry.raw,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class BruteForceTracker:
    """Tracks failed auth attempts per IP to surface brute-force campaigns."""
    _counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _first_seen: dict[str, datetime] = field(default_factory=dict)
    threshold: int = 5

    def record(self, ip: str, ts: datetime | None) -> bool:
        """Record a failure. Returns True when the threshold is first crossed."""
        self._counts[ip] += 1
        if ip not in self._first_seen:
            self._first_seen[ip] = ts or datetime.now()
        return self._counts[ip] == self.threshold

    def count(self, ip: str) -> int:
        return self._counts.get(ip, 0)

    def first_seen(self, ip: str) -> datetime | None:
        return self._first_seen.get(ip)

    def summary(self) -> dict[str, dict]:
        return {
            ip: {"failures": cnt, "first_seen": self._first_seen.get(ip)}
            for ip, cnt in self._counts.items()
            if cnt >= self.threshold
        }


class LogStrikeAnalyzer:
    """
    LogStrike main analysis engine.

    Author: Ernest Kosmatko (@Ernest-Kosmatko)

    Usage
    -----
    analyzer = LogStrikeAnalyzer()
    for finding in analyzer.analyze_file("auth.log"):
        print(finding)
    """

    def __init__(self, brute_force_threshold: int = 5, rules: list[ThreatRule] | None = None):
        self.rules = rules or RULES
        self.brute_tracker = BruteForceTracker(threshold=brute_force_threshold)
        self.findings: list[Finding] = []
        self._stats: dict[str, int] = defaultdict(int)

    def analyze_line(self, raw_line: str) -> list[Finding]:
        """Analyse a single raw log line; return any new Findings."""
        entry = parse_line(raw_line)
        return self._process_entry(entry)

    def analyze_file(self, path: str | Path) -> Iterator[Finding]:
        """Yield Findings as each line of a log file is processed."""
        for entry in parse_file(path):
            self._stats["lines"] += 1
            for finding in self._process_entry(entry):
                yield finding

    def summary(self) -> dict:
        """Return a statistical summary of the analysis session."""
        severity_counts: dict[str, int] = defaultdict(int)
        tactic_counts: dict[str, int] = defaultdict(int)
        ip_counts: dict[str, int] = defaultdict(int)

        for f in self.findings:
            severity_counts[f.rule.severity.value] += 1
            tactic_counts[f.rule.mitre_tactic] += 1
            if f.entry.ip:
                ip_counts[f.entry.ip] += 1

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_lines_processed": self._stats["lines"],
            "total_findings": len(self.findings),
            "findings_by_severity": dict(severity_counts),
            "findings_by_tactic": dict(tactic_counts),
            "top_offending_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
            "brute_force_sources": self.brute_tracker.summary(),
        }

    def reset(self) -> None:
        """Clear all state for a fresh analysis session."""
        self.findings.clear()
        self.brute_tracker = BruteForceTracker(threshold=self.brute_tracker.threshold)
        self._stats.clear()

    def _process_entry(self, entry: LogEntry) -> list[Finding]:
        new_findings: list[Finding] = []
        for rule in self.rules:
            if rule.match(entry.raw):
                f = Finding(rule=rule, entry=entry)
                self.findings.append(f)
                new_findings.append(f)
                self._stats["findings"] += 1
                if "LS-001" == rule.id and entry.ip:
                    if not _is_private(entry.ip):
                        self.brute_tracker.record(entry.ip, entry.timestamp)
        return new_findings


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
