"""Utility helpers for file handling and summarization."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".so"
}

IGNORE_DIR_NAMES = {
    ".git", "__pycache__", ".venv", "node_modules", "dist", "build", "output"
}


def should_skip_path(path: Path) -> bool:
    return any(part in IGNORE_DIR_NAMES for part in path.parts)



def is_probably_text_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return False
    try:
        with path.open("rb") as handle:
            chunk = handle.read(2048)
        if b"\x00" in chunk:
            return False
        return True
    except OSError:
        return False



def safe_read_lines(path: Path) -> list[str]:
    encodings = ["utf-8", "utf-8-sig", "latin-1"]
    for encoding in encodings:
        try:
            with path.open("r", encoding=encoding, errors="strict") as handle:
                return handle.readlines()
        except (UnicodeDecodeError, OSError):
            continue
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            return handle.readlines()
    except OSError:
        return []



def severity_sort_key(severity: str) -> int:
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return order.get(severity, 99)



def relative_to(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)



def chunked(iterable: Iterable, size: int):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch
