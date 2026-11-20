#!/usr/bin/env python3
"""
Run before every release. Checks all required conditions.
Exit 0 = ready to release. Exit 1 = not ready.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from actionscope import __version__


def check(checks: list[bool], name: str, passed: bool, detail: str = "") -> None:
    status = "✅" if passed else "❌"
    print(f"{status} {name}" + (f": {detail}" if detail else ""))
    checks.append(passed)


def validate_citation_metadata(path: Path, expected_version: str) -> tuple[bool, str]:
    """Validate release-critical citation fields without raising."""
    try:
        citation = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return False, str(exc)
    if not isinstance(citation, dict):
        return False, "CITATION.cff must contain a YAML mapping"

    citation_version = str(citation.get("version", ""))
    return (
        citation.get("cff-version") == "1.2.0"
        and citation.get("repository-code") == "https://github.com/r12habh/ActionScope"
        and citation_version == expected_version,
        f"software version: {citation_version or 'missing'}",
    )


def main() -> int:
    """Run the release-readiness checks and return a process exit code."""
    checks: list[bool] = []

    result = subprocess.run(["pytest", "tests/", "-q"], capture_output=True, text=True)
    check(
        checks,
        "Tests pass",
        result.returncode == 0,
        result.stdout.strip().split(chr(10))[-1] if result.stdout else "no output",
    )

    result = subprocess.run(["ruff", "check", "actionscope/"], capture_output=True)
    check(checks, "Ruff lint clean", result.returncode == 0)

    result = subprocess.run(
        ["python", "-m", "build", "--no-isolation"],
        capture_output=True,
    )
    check(checks, "Package builds", result.returncode == 0)

    result = subprocess.run(
        ["actionscope", "--version"], capture_output=True, text=True
    )
    check(checks, "CLI responds", result.returncode == 0, result.stdout.strip())

    result = subprocess.run(
        ["actionscope", "scan", ".", "--output-format", "json"],
        capture_output=True,
        text=True,
    )
    try:
        data = json.loads(result.stdout)
        detail = f"overall_risk: {data.get('overall_risk')}"
    except Exception:
        check(
            checks,
            "Self-scan produces valid JSON",
            False,
            result.stderr[:100] if result.stderr else "no output",
        )
    else:
        check(checks, "Self-scan produces valid JSON", True, detail)

    readme = Path("README.md").read_text(encoding="utf-8")
    check(checks, "README has pip install", "pip install actionscope" in readme)
    check(checks, "README has GitHub Action example", "uses:" in readme)

    community_files = [
        "CITATION.cff",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "SECURITY.md",
        "SUPPORT.md",
    ]
    missing_community_files = [
        path for path in community_files if not Path(path).is_file()
    ]
    check(
        checks,
        "Community health files present",
        not missing_community_files,
        ", ".join(missing_community_files)
        if missing_community_files
        else "all present",
    )

    citation_valid, citation_detail = validate_citation_metadata(
        Path("CITATION.cff"), __version__
    )
    check(checks, "Citation metadata valid", citation_valid, citation_detail)

    ready = all(checks)
    print(f"\n{'Ready to release!' if ready else 'Fix issues before releasing.'}")
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
