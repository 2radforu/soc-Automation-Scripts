"""log_parser.py

Enhanced log parser CLI for SOC Automation Scripts.

Features:
- substring or regex pattern matching (--pattern, --regex)
- output as stamped text or JSON Lines (--format json|text)
- functions suitable for unit testing
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from typing import Iterable


def find_matches(lines: Iterable[str], pattern: str, use_regex: bool = False) -> Iterable[str]:
    """Yield lines that match the provided pattern.

    - If use_regex is False, performs a simple substring check.
    - If use_regex is True, treats `pattern` as a regular expression.
    """
    if use_regex:
        prog = re.compile(pattern)
        for line in lines:
            if prog.search(line):
                yield line
    else:
        for line in lines:
            if pattern in line:
                yield line


def format_alert_text(line: str) -> str:
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    return f"[{ts}] [ALERT]: {line.rstrip()}\n"


def format_alert_json(line: str, rule: str) -> str:
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event": line.rstrip(),
        "rule": rule,
        "severity": "high",
    }
    return json.dumps(payload, ensure_ascii=False) + "\n"


def parse_logs(input_path: str, output_path: str | None, pattern: str = "Malicious",
               use_regex: bool = False, out_format: str = "text") -> int:
    """Parse the input file and write alerts to output (or stdout when output_path is None).

    Returns the number of alerts written.
    """
    count = 0
    rule = ("regex: %s" % pattern) if use_regex else ("pattern: %s" % pattern)

    with open(input_path, "r", encoding="utf-8") as inf:
        matches = list(find_matches(inf, pattern, use_regex))

    if output_path:
        out_file = open(output_path, "a", encoding="utf-8")
    else:
        out_file = None

    try:
        for line in matches:
            if out_format == "json":
                entry = format_alert_json(line, rule)
            else:
                entry = format_alert_text(line)

            if out_file:
                out_file.write(entry)
            else:
                print(entry, end="")
            count += 1
    finally:
        if out_file:
            out_file.close()

    return count


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Simple log parser for SOC Automation Scripts")
    p.add_argument("--input", "-i", required=True, help="Path to input log file")
    p.add_argument("--output", "-o", help="Path to output file (append). If omitted, prints to stdout")
    p.add_argument("--pattern", "-p", default="Malicious", help="Substring or regex to match (default: 'Malicious')")
    p.add_argument("--regex", "-r", action="store_true", help="Treat --pattern as a regular expression")
    p.add_argument("--format", "-f", choices=("text", "json"), default="text", help="Output format: text (stamped) or json (JSON Lines)")
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_argparser()
    args = parser.parse_args(argv)
    count = parse_logs(args.input, args.output, args.pattern, args.regex, args.format)
    print(f"Process finished! {count} alerts found.")


if __name__ == "__main__":
    main()
