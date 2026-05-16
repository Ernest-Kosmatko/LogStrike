"""
LogStrike — Command Line Interface

Author  : Ernest Kosmatko (@Ernest-Kosmatko)
GitHub  : https://github.com/Ernest-Kosmatko/LogStrike
License : MIT © 2024 Ernest Kosmatko

Usage: logstrike [OPTIONS] LOG_FILE [LOG_FILE ...]
       python -m logstrike [OPTIONS] LOG_FILE [LOG_FILE ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import LogStrikeAnalyzer
from .reporter import print_banner, print_finding, print_summary, save_csv, save_json
from .rules import Severity


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logstrike",
        description=(
            "LogStrike — Real-time log analysis & threat detection\n"
            "Maps findings to the MITRE ATT&CK® framework\n\n"
            "Author : Ernest Kosmatko (@Ernest-Kosmatko)\n"
            "GitHub : https://github.com/Ernest-Kosmatko/LogStrike"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  logstrike auth.log\n"
            "  logstrike -s HIGH access.log auth.log --json report.json\n"
            "  logstrike --tail /var/log/auth.log\n"
            "  cat auth.log | logstrike -\n"
        ),
    )
    p.add_argument(
        "files",
        nargs="*",
        metavar="LOG_FILE",
        help="Log files to analyse. Use '-' to read from stdin.",
    )
    p.add_argument(
        "--tail", "-t",
        metavar="FILE",
        help="Watch a file in real-time (like tail -f).",
    )
    p.add_argument(
        "--severity", "-s",
        choices=[s.value for s in Severity],
        default="LOW",
        help="Minimum severity to display (default: LOW).",
    )
    p.add_argument(
        "--json",
        metavar="FILE",
        dest="json_output",
        help="Save full JSON report to FILE.",
    )
    p.add_argument(
        "--csv",
        metavar="FILE",
        dest="csv_output",
        help="Save CSV report to FILE.",
    )
    p.add_argument(
        "--brute-threshold",
        type=int,
        default=5,
        metavar="N",
        help="Failed auth attempts before brute-force alert (default: 5).",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress per-finding output; only print summary.",
    )
    p.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner.",
    )
    p.add_argument(
        "--no-summary",
        action="store_true",
        help="Suppress the summary block.",
    )
    p.add_argument(
        "--version", "-v",
        action="version",
        version="LogStrike 1.0.0 — by Ernest Kosmatko (@Ernest-Kosmatko)",
    )
    return p


def _sev_index(sev: Severity) -> int:
    return list(Severity).index(sev)


def run_analysis(
    analyzer: LogStrikeAnalyzer,
    min_severity: Severity,
    quiet: bool,
    file_paths: list[Path | None],
) -> None:
    min_idx = _sev_index(min_severity)
    for path in file_paths:
        if path is None:
            for line in sys.stdin:
                for finding in analyzer.analyze_line(line):
                    if _sev_index(finding.severity) >= min_idx and not quiet:
                        print_finding(finding)
        else:
            for finding in analyzer.analyze_file(path):
                if _sev_index(finding.severity) >= min_idx and not quiet:
                    print_finding(finding)


def tail_mode(
    analyzer: LogStrikeAnalyzer,
    path: Path,
    min_severity: Severity,
    quiet: bool,
) -> None:
    import time
    min_idx = _sev_index(min_severity)
    print(f"[LogStrike] Tailing {path} — press Ctrl-C to stop\n")
    try:
        with open(path, "r", errors="replace") as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                for finding in analyzer.analyze_line(line):
                    if _sev_index(finding.severity) >= min_idx and not quiet:
                        print_finding(finding)
    except KeyboardInterrupt:
        print("\n[LogStrike] Stopped.")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.files and not args.tail:
        parser.print_help()
        return 0

    if not getattr(args, "no_banner", False):
        print_banner()

    min_sev = Severity(args.severity)
    analyzer = LogStrikeAnalyzer(brute_force_threshold=args.brute_threshold)

    if args.tail:
        tail_mode(analyzer, Path(args.tail), min_sev, args.quiet)
    else:
        paths: list[Path | None] = []
        for f in args.files:
            paths.append(None if f == "-" else Path(f))
        run_analysis(analyzer, min_sev, args.quiet, paths)

    if not args.no_summary:
        print_summary(analyzer)

    if args.json_output:
        save_json(analyzer, args.json_output)
        print(f"[LogStrike] JSON report saved → {args.json_output}")

    if args.csv_output:
        save_csv(analyzer, args.csv_output)
        print(f"[LogStrike] CSV report saved  → {args.csv_output}")

    for f in analyzer.findings:
        if f.severity == Severity.CRITICAL:
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
