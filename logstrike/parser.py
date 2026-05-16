"""
LogStrike — Log Parser
Normalises diverse log formats into a unified LogEntry structure.

Author  : Ernest Kosmatko (@Ernest-Kosmatko)
GitHub  : https://github.com/Ernest-Kosmatko/LogStrike
License : MIT © 2024 Ernest Kosmatko

Supported formats:
  - Linux auth.log / syslog
  - Apache / Nginx combined access log
  - Windows Event Log (plain-text export)
  - Generic / unknown (fallback)
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional


class LogSource(str, Enum):
    AUTH = "auth"
    SYSLOG = "syslog"
    APACHE = "apache"
    NGINX = "nginx"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


@dataclass
class LogEntry:
    raw: str
    source: LogSource
    timestamp: Optional[datetime] = None
    host: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    message: str = ""
    ip: Optional[str] = None
    user: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def __str__(self) -> str:
        ts = self.timestamp.isoformat() if self.timestamp else "no-timestamp"
        return f"[{ts}] [{self.source.value}] {self.message}"


# ── Compiled patterns ────────────────────────────────────────────────────────

_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$"
)

_APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

_APACHE_TIME_RE = re.compile(
    r"(?P<day>\d{2})/(?P<month>\w{3})/(?P<year>\d{4})"
    r":(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})"
)

_WIN_EVT_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r".*?EventID:\s*(?P<event_id>\d+).*?(?:Message:\s*(?P<msg>.+))?$"
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:user|for)\s+(\w+)", re.IGNORECASE)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _detect_source(line: str) -> LogSource:
    if re.match(r"^\w{3}\s+\d", line) and ("sshd" in line or "sudo" in line or "PAM" in line):
        return LogSource.AUTH
    if re.match(r"^\w{3}\s+\d", line):
        return LogSource.SYSLOG
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}\s", line):
        return LogSource.APACHE
    if re.match(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", line) and "EventID" in line:
        return LogSource.WINDOWS
    return LogSource.UNKNOWN


def _parse_syslog(line: str, source: LogSource) -> LogEntry:
    m = _SYSLOG_RE.match(line)
    entry = LogEntry(raw=line, source=source)
    if m:
        year = datetime.now().year
        try:
            entry.timestamp = datetime(
                year,
                _MONTH_MAP.get(m.group("month"), 1),
                int(m.group("day")),
                *[int(x) for x in m.group("time").split(":")],
            )
        except ValueError:
            pass
        entry.host = m.group("host")
        entry.process = m.group("process")
        entry.pid = int(m.group("pid")) if m.group("pid") else None
        entry.message = m.group("msg")
    else:
        entry.message = line

    ip_m = _IP_RE.search(entry.message)
    if ip_m:
        entry.ip = ip_m.group(0)
    user_m = _USER_RE.search(entry.message)
    if user_m:
        entry.user = user_m.group(1)
    return entry


def _parse_apache(line: str) -> LogEntry:
    entry = LogEntry(raw=line, source=LogSource.APACHE)
    m = _APACHE_COMBINED_RE.match(line)
    if m:
        entry.ip = m.group("ip")
        entry.user = m.group("user") if m.group("user") != "-" else None
        entry.message = m.group("request")
        entry.extra["status"] = m.group("status")
        entry.extra["size"] = m.group("size")
        if m.group("ua"):
            entry.extra["user_agent"] = m.group("ua")
        tm = _APACHE_TIME_RE.search(m.group("time"))
        if tm:
            try:
                entry.timestamp = datetime(
                    int(tm.group("year")),
                    _MONTH_MAP.get(tm.group("month"), 1),
                    int(tm.group("day")),
                    int(tm.group("hour")),
                    int(tm.group("min")),
                    int(tm.group("sec")),
                )
            except ValueError:
                pass
    else:
        entry.message = line
    return entry


def _parse_windows(line: str) -> LogEntry:
    entry = LogEntry(raw=line, source=LogSource.WINDOWS)
    m = _WIN_EVT_RE.match(line)
    if m:
        try:
            entry.timestamp = datetime.fromisoformat(f"{m.group('date')} {m.group('time')}")
        except ValueError:
            pass
        entry.extra["event_id"] = m.group("event_id")
        entry.message = m.group("msg") or line
    else:
        entry.message = line
    ip_m = _IP_RE.search(entry.message)
    if ip_m:
        entry.ip = ip_m.group(0)
    return entry


def parse_line(line: str) -> LogEntry:
    """Parse a single log line into a LogEntry."""
    line = line.rstrip("\n\r")
    if not line.strip():
        return LogEntry(raw=line, source=LogSource.UNKNOWN, message=line)

    source = _detect_source(line)
    if source in (LogSource.AUTH, LogSource.SYSLOG):
        return _parse_syslog(line, source)
    if source == LogSource.APACHE:
        return _parse_apache(line)
    if source == LogSource.WINDOWS:
        return _parse_windows(line)

    entry = LogEntry(raw=line, source=LogSource.UNKNOWN, message=line)
    ip_m = _IP_RE.search(line)
    if ip_m:
        entry.ip = ip_m.group(0)
    return entry


def parse_file(path: str | Path) -> Iterator[LogEntry]:
    """Yield LogEntry objects for every line in a file."""
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            yield parse_line(line)
