"""Scanning engine for the OpenClaw Security Review Toolkit."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .rules import RULES, SUPPORTED_EXTENSIONS
from .utils import is_probably_text_file, relative_to, safe_read_lines, should_skip_path, severity_sort_key


class SecurityScanner:
    def __init__(self, target_dir: str | Path):
        self.target_dir = Path(target_dir).resolve()
        self.compiled_rules = [
            {**rule, "regex": re.compile(rule["pattern"])} for rule in RULES
        ]

    def discover_files(self) -> list[Path]:
        files: list[Path] = []
        for path in self.target_dir.rglob("*"):
            if not path.is_file():
                continue
            if should_skip_path(path):
                continue
            if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            if not is_probably_text_file(path):
                continue
            files.append(path)
        return sorted(files)

    def scan(self) -> dict[str, Any]:
        discovered = self.discover_files()
        findings: list[dict[str, Any]] = []

        for path in discovered:
            lines = safe_read_lines(path)
            for line_number, line in enumerate(lines, start=1):
                for rule in self.compiled_rules:
                    if rule["regex"].search(line):
                        findings.append(
                            {
                                "rule_id": rule["id"],
                                "category": rule["category"],
                                "severity": rule["severity"],
                                "description": rule["description"],
                                "file": relative_to(path, self.target_dir),
                                "line": line_number,
                                "match": line.strip()[:200],
                            }
                        )

        findings = sorted(
            findings,
            key=lambda f: (
                severity_sort_key(f["severity"]),
                f["category"],
                f["file"],
                f["line"],
                f["rule_id"],
            ),
        )

        return self._build_report(discovered, findings)

    def _build_report(self, files: list[Path], findings: list[dict[str, Any]]) -> dict[str, Any]:
        severity_counts = Counter(f["severity"] for f in findings)
        category_counts = Counter(f["category"] for f in findings)
        file_counts = Counter(f["file"] for f in findings)
        grouped_by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            grouped_by_category[finding["category"]].append(finding)

        metadata = {
            "tool_name": "OpenClaw Security Review Toolkit",
            "scan_target": str(self.target_dir),
            "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "files_scanned": len(files),
            "findings_total": len(findings),
        }

        summary = {
            "severity_counts": dict(severity_counts),
            "category_counts": dict(category_counts),
            "top_risky_files": [
                {"file": file_name, "count": count}
                for file_name, count in file_counts.most_common(10)
            ],
        }

        return {
            "metadata": metadata,
            "summary": summary,
            "findings": findings,
            "findings_by_category": dict(grouped_by_category),
        }
