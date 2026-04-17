"""CLI entry point for the OpenClaw Security Review Toolkit."""
from __future__ import annotations

import argparse
from pathlib import Path

from .engine import SecurityScanner
from .reporter import print_summary, write_json, write_markdown



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a directory for potentially risky security patterns."
    )
    parser.add_argument(
        "target",
        help="Path to the directory you want to scan. Example: ./sample_target",
    )
    parser.add_argument(
        "--json-output",
        default="output/findings.json",
        help="Path for JSON report output. Default: output/findings.json",
    )
    parser.add_argument(
        "--md-output",
        default="output/findings.md",
        help="Path for Markdown report output. Default: output/findings.md",
    )
    return parser



def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists() or not target.is_dir():
        parser.error(f"Target directory does not exist or is not a directory: {target}")

    scanner = SecurityScanner(target)
    report = scanner.scan()

    print_summary(report)
    write_json(report, args.json_output)
    write_markdown(report, args.md_output)

    print(f"JSON report written to: {Path(args.json_output).resolve()}")
    print(f"Markdown report written to: {Path(args.md_output).resolve()}")


if __name__ == "__main__":
    main()
