#!/usr/bin/env python3
"""
Bump ActionScope version across all files.
Usage: python scripts/bump_version.py 0.5.0 0.6.0 2026-12-01
"""

from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path


def bump_version(old: str, new: str, release_date: str) -> None:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", release_date):
        raise ValueError("release date must use YYYY-MM-DD format")
    date.fromisoformat(release_date)

    files_to_update = [
        "pyproject.toml",
        "actionscope/__init__.py",
        "action.yml",
        "CITATION.cff",
    ]

    for filepath in files_to_update:
        path = Path(filepath)
        content = path.read_text(encoding="utf-8")
        updated = content.replace(old, new)
        citation_has_target_version = filepath == "CITATION.cff" and re.search(
            rf"(?m)^version:\s*['\"]?{re.escape(new)}['\"]?\s*$", updated
        )
        if citation_has_target_version:
            updated = re.sub(
                r"(?m)^date-released: .+$",
                f"date-released: {release_date}",
                updated,
            )
        if content != updated:
            path.write_text(updated, encoding="utf-8")
            print(f"Updated {filepath}: {old} -> {new}")
        else:
            print(f"No change in {filepath}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(
            "Usage: python scripts/bump_version.py OLD_VERSION NEW_VERSION YYYY-MM-DD"
        )
        sys.exit(1)
    try:
        bump_version(sys.argv[1], sys.argv[2], sys.argv[3])
    except ValueError as exc:
        print(f"Invalid release date: {exc}")
        sys.exit(1)
