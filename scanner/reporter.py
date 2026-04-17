"""Reporting helpers for terminal, JSON, and Markdown outputs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .utils import severity_sort_key


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def print_summary(report: dict[str, Any]) -> None:
    metadata = report["metadata"]
    summary = report["summary"]

    print("=" * 72)
    print(metadata["tool_name"])
    print("=" * 72)
    print(f"Target:          {metadata['scan_target']}")
    print(f"Scanned at UTC:  {metadata['scan_timestamp_utc']}")
    print(f"Files scanned:   {metadata['files_scanned']}")
    print(f"Total findings:  {metadata['findings_total']}")
    print("-" * 72)

    print("Findings by severity:")
    for severity in SEVERITY_ORDER:
        count = summary["severity_counts"].get(severity, 0)
        if count:
            print(f"  - {severity:<8} {count}")
    if not summary["severity_counts"]:
        print("  - No findings")

    print("-" * 72)
    print("Top risky files:")
    if summary["top_risky_files"]:
        for item in summary["top_risky_files"][:5]:
            print(f"  - {item['file']} ({item['count']} findings)")
    else:
        print("  - No risky files identified")

    print("-" * 72)
    print("Sample findings:")
    sample = report["findings"][:5]
    if sample:
        for finding in sample:
            print(
                f"  - [{finding['severity']}] {finding['rule_id']} in {finding['file']}:{finding['line']}"
            )
            print(f"    {finding['description']}")
            print(f"    Code: {finding['match']}")
    else:
        print("  - No findings")
    print("=" * 72)



def write_json(report: dict[str, Any], output_path: str | Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)



def write_markdown(report: dict[str, Any], output_path: str | Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    metadata = report["metadata"]
    summary = report["summary"]
    findings_by_category = report["findings_by_category"]

    lines: list[str] = []
    lines.append("# OpenClaw Security Review Toolkit Report")
    lines.append("")
    lines.append("## Scan Metadata")
    lines.append("")
    lines.append(f"- **Target:** `{metadata['scan_target']}`")
    lines.append(f"- **Scan time (UTC):** `{metadata['scan_timestamp_utc']}`")
    lines.append(f"- **Files scanned:** {metadata['files_scanned']}")
    lines.append(f"- **Total findings:** {metadata['findings_total']}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("### Findings by Severity")
    lines.append("")
    for severity in sorted(summary["severity_counts"], key=severity_sort_key):
        lines.append(f"- **{severity}:** {summary['severity_counts'][severity]}")
    if not summary["severity_counts"]:
        lines.append("- No findings")
    lines.append("")
    lines.append("### Findings by Category")
    lines.append("")
    for category, count in sorted(summary["category_counts"].items()):
        lines.append(f"- **{category}:** {count}")
    if not summary["category_counts"]:
        lines.append("- No findings")
    lines.append("")
    lines.append("### Top Risky Files")
    lines.append("")
    for item in summary["top_risky_files"][:10]:
        lines.append(f"- `{item['file']}` — {item['count']} findings")
    if not summary["top_risky_files"]:
        lines.append("- None")
    lines.append("")
    lines.append("## Detailed Findings")
    lines.append("")

    if not findings_by_category:
        lines.append("No findings were detected.")
    else:
        for category in sorted(findings_by_category):
            lines.append(f"### {category}")
            lines.append("")
            findings = sorted(
                findings_by_category[category],
                key=lambda f: (severity_sort_key(f["severity"]), f["file"], f["line"]),
            )
            for finding in findings:
                lines.append(
                    f"- **[{finding['severity']}] {finding['rule_id']}** in `{finding['file']}` line {finding['line']}"
                )
                lines.append(f"  - Description: {finding['description']}")
                lines.append(f"  - Code: `{finding['match']}`")
            lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    lines.append("- Replace shell-based command execution with safer APIs and strict allowlists.")
    lines.append("- Remove hardcoded secrets and use environment variables or secret managers.")
    lines.append("- Enforce strong authentication and role-based access control on orchestration interfaces.")
    lines.append("- Add input validation, output encoding, and safe deserialization practices.")
    lines.append("- Improve logging and auditing around sensitive actions such as remote command execution.")

    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
