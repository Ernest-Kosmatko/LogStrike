"""
LogStrike — Detection Rules Engine
Mapped to MITRE ATT&CK® framework.

Author  : Ernest Kosmatko (@Ernest-Kosmatko)
GitHub  : https://github.com/Ernest-Kosmatko/LogStrike
License : MIT © 2024 Ernest Kosmatko

Each rule carries:
  - Unique rule ID  (LS-XXX)
  - Severity level  (INFO / LOW / MEDIUM / HIGH / CRITICAL)
  - MITRE tactic, technique ID, and direct ATT&CK URL
  - Compiled regex pattern (matched against raw log lines)
  - Tags for downstream filtering / grouping
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatRule:
    id: str
    name: str
    description: str
    severity: Severity
    mitre_tactic: str
    mitre_technique: str
    mitre_url: str
    pattern: re.Pattern
    tags: list[str] = field(default_factory=list)

    def match(self, line: str) -> Optional[re.Match]:
        return self.pattern.search(line)


RULES: list[ThreatRule] = [

    # ── Brute Force / Credential Access ─────────────────────────────────────
    ThreatRule(
        id="LS-001",
        name="SSH Brute Force Attempt",
        description="Multiple failed SSH authentication attempts from a single source.",
        severity=Severity.HIGH,
        mitre_tactic="Credential Access",
        mitre_technique="T1110.001 – Brute Force: Password Guessing",
        mitre_url="https://attack.mitre.org/techniques/T1110/001/",
        pattern=re.compile(
            r"(Failed password|Invalid user|authentication failure)",
            re.IGNORECASE,
        ),
        tags=["brute-force", "ssh", "authentication"],
    ),

    ThreatRule(
        id="LS-002",
        name="SSH Root Login Attempt",
        description="Direct root login attempt via SSH.",
        severity=Severity.CRITICAL,
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1078.003 – Valid Accounts: Local Accounts",
        mitre_url="https://attack.mitre.org/techniques/T1078/003/",
        pattern=re.compile(
            r"(Failed password|Invalid user).*root.*ssh",
            re.IGNORECASE,
        ),
        tags=["ssh", "root", "privilege-escalation"],
    ),

    # ── Web Attacks ──────────────────────────────────────────────────────────
    ThreatRule(
        id="LS-003",
        name="SQL Injection Attempt",
        description="SQL injection payload detected in web request.",
        severity=Severity.CRITICAL,
        mitre_tactic="Initial Access",
        mitre_technique="T1190 – Exploit Public-Facing Application",
        mitre_url="https://attack.mitre.org/techniques/T1190/",
        pattern=re.compile(
            r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b"
            r"|1=1|'--|\bor\b\s+\d+=\d+|sleep\(\d+\)|benchmark\(\d+)",
            re.IGNORECASE,
        ),
        tags=["sqli", "web", "injection"],
    ),

    ThreatRule(
        id="LS-004",
        name="Cross-Site Scripting (XSS) Attempt",
        description="XSS payload detected in web request.",
        severity=Severity.HIGH,
        mitre_tactic="Initial Access",
        mitre_technique="T1190 – Exploit Public-Facing Application",
        mitre_url="https://attack.mitre.org/techniques/T1190/",
        pattern=re.compile(
            r"(<script[\s>]|javascript:|onerror\s*=|onload\s*=|eval\s*\(|document\.cookie)",
            re.IGNORECASE,
        ),
        tags=["xss", "web", "injection"],
    ),

    ThreatRule(
        id="LS-005",
        name="Path Traversal Attempt",
        description="Directory traversal payload detected.",
        severity=Severity.HIGH,
        mitre_tactic="Discovery",
        mitre_technique="T1083 – File and Directory Discovery",
        mitre_url="https://attack.mitre.org/techniques/T1083/",
        pattern=re.compile(
            r"(\.\./){2,}|(%2e%2e%2f){2,}|(\.\./|%2e%2e/)+(etc/passwd|windows/system32)",
            re.IGNORECASE,
        ),
        tags=["path-traversal", "web", "lfi"],
    ),

    ThreatRule(
        id="LS-006",
        name="Web Shell Upload / Access",
        description="Possible web shell file access or upload detected.",
        severity=Severity.CRITICAL,
        mitre_tactic="Persistence",
        mitre_technique="T1505.003 – Server Software Component: Web Shell",
        mitre_url="https://attack.mitre.org/techniques/T1505/003/",
        pattern=re.compile(
            r"(cmd\.php|shell\.php|c99\.php|r57\.php|b374k|wso\.php"
            r"|upload.*\.php|\.php\?cmd=|\.php\?exec=)",
            re.IGNORECASE,
        ),
        tags=["webshell", "persistence", "upload"],
    ),

    # ── Reconnaissance ───────────────────────────────────────────────────────
    ThreatRule(
        id="LS-007",
        name="Port Scan Detection",
        description="Rapid sequential connection attempts indicating a port scan.",
        severity=Severity.MEDIUM,
        mitre_tactic="Reconnaissance",
        mitre_technique="T1046 – Network Service Discovery",
        mitre_url="https://attack.mitre.org/techniques/T1046/",
        pattern=re.compile(
            r"(nmap|masscan|zmap|port scan|SYN scan|connection refused.*\d{2,5})",
            re.IGNORECASE,
        ),
        tags=["recon", "scan", "network"],
    ),

    # ── Privilege Escalation ─────────────────────────────────────────────────
    ThreatRule(
        id="LS-008",
        name="Sudo Privilege Escalation",
        description="Unauthorized or repeated sudo usage detected.",
        severity=Severity.HIGH,
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1548.003 – Abuse Elevation Control: Sudo",
        mitre_url="https://attack.mitre.org/techniques/T1548/003/",
        pattern=re.compile(
            r"(sudo(\[\d+\])?:.*incorrect password|sudo(\[\d+\])?:.*NOT in sudoers|sudo(\[\d+\])?:.*command not allowed)",
            re.IGNORECASE,
        ),
        tags=["sudo", "privilege-escalation", "linux"],
    ),

    ThreatRule(
        id="LS-009",
        name="Suspicious SUID Binary Execution",
        description="Execution of a setuid binary that may allow privilege escalation.",
        severity=Severity.HIGH,
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1548.001 – Abuse Elevation Control: Setuid/Setgid",
        mitre_url="https://attack.mitre.org/techniques/T1548/001/",
        pattern=re.compile(
            r"(chmod\s+[46]\d\d\d|chmod\s+u\+s|/usr/bin/find.*-exec|"
            r"/usr/bin/vim.*-c.*:!/bin|/usr/bin/less.*!/bin/sh)",
            re.IGNORECASE,
        ),
        tags=["suid", "privilege-escalation", "linux"],
    ),

    # ── Persistence ──────────────────────────────────────────────────────────
    ThreatRule(
        id="LS-010",
        name="Crontab Modification",
        description="Modification of crontab for persistence.",
        severity=Severity.HIGH,
        mitre_tactic="Persistence",
        mitre_technique="T1053.003 – Scheduled Task/Job: Cron",
        mitre_url="https://attack.mitre.org/techniques/T1053/003/",
        pattern=re.compile(
            r"(crontab\s+-[el]|/etc/cron\.(d|daily|hourly|weekly|monthly)|"
            r"/var/spool/cron)",
            re.IGNORECASE,
        ),
        tags=["cron", "persistence", "linux"],
    ),

    # ── Exfiltration ─────────────────────────────────────────────────────────
    ThreatRule(
        id="LS-011",
        name="Large Outbound Data Transfer",
        description="Unusually large outbound transfer that may indicate data exfiltration.",
        severity=Severity.HIGH,
        mitre_tactic="Exfiltration",
        mitre_technique="T1048 – Exfiltration Over Alternative Protocol",
        mitre_url="https://attack.mitre.org/techniques/T1048/",
        pattern=re.compile(
            r"(bytes_sent=[5-9]\d{8,}|bytes_sent=[1-9]\d{9,}|"
            r"transferred\s+[5-9]\d{2,}\s*MB|data exfil)",
            re.IGNORECASE,
        ),
        tags=["exfiltration", "data-loss", "network"],
    ),

    # ── Malware / C2 ─────────────────────────────────────────────────────────
    ThreatRule(
        id="LS-012",
        name="Reverse Shell Attempt",
        description="Command pattern consistent with reverse shell establishment.",
        severity=Severity.CRITICAL,
        mitre_tactic="Command and Control",
        mitre_technique="T1059.004 – Command and Scripting Interpreter: Unix Shell",
        mitre_url="https://attack.mitre.org/techniques/T1059/004/",
        pattern=re.compile(
            r"(bash\s+-i\s+>&|/dev/tcp/|nc\s+-e\s+/bin/(ba)?sh"
            r"|python.*-c.*socket.*exec|perl.*-e.*socket.*exec"
            r"|mkfifo.*nc.*sh)",
            re.IGNORECASE,
        ),
        tags=["reverse-shell", "c2", "execution"],
    ),

    ThreatRule(
        id="LS-013",
        name="Cryptocurrency Miner Detected",
        description="Process or network traffic matching known crypto-mining patterns.",
        severity=Severity.HIGH,
        mitre_tactic="Impact",
        mitre_technique="T1496 – Resource Hijacking",
        mitre_url="https://attack.mitre.org/techniques/T1496/",
        pattern=re.compile(
            r"(xmrig|stratum\+tcp|pool\.minexmr|cryptonight|monero"
            r"|coinhive|minerd|cpuminer)",
            re.IGNORECASE,
        ),
        tags=["cryptominer", "resource-hijacking", "malware"],
    ),

    # ── Account Manipulation ─────────────────────────────────────────────────
    ThreatRule(
        id="LS-014",
        name="New User Account Created",
        description="New OS user account created — may indicate persistence or lateral movement.",
        severity=Severity.MEDIUM,
        mitre_tactic="Persistence",
        mitre_technique="T1136.001 – Create Account: Local Account",
        mitre_url="https://attack.mitre.org/techniques/T1136/001/",
        pattern=re.compile(
            r"(useradd|adduser|net user.*\/add|New-LocalUser)",
            re.IGNORECASE,
        ),
        tags=["account-creation", "persistence"],
    ),

    ThreatRule(
        id="LS-015",
        name="Password Change Detected",
        description="User password changed outside of expected maintenance windows.",
        severity=Severity.MEDIUM,
        mitre_tactic="Credential Access",
        mitre_technique="T1098 – Account Manipulation",
        mitre_url="https://attack.mitre.org/techniques/T1098/",
        pattern=re.compile(
            r"(passwd.*changed|chpasswd|net user.*/passwordreq|password successfully changed)",
            re.IGNORECASE,
        ),
        tags=["credential-access", "account-manipulation"],
    ),
]
