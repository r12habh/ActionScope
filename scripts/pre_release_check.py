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

checks = []


def check(name: str, passed: bool, detail: str = "") -> None:
    status = "✅" if passed else "❌"
    print(f"{status} {name}" + (f": {detail}" if detail else ""))
    checks.append(passed)


result = subprocess.run(["pytest", "tests/", "-q"], capture_output=True, text=True)
check(
    "Tests pass",
    result.returncode == 0,
    f"{result.stdout.strip().split(chr(10))[-1] if result.stdout else 'no output'}",
)

result = subprocess.run(["ruff", "check", "actionscope/"], capture_output=True)
check("Ruff lint clean", result.returncode == 0)

result = subprocess.run(
    ["python", "-m", "build", "--no-isolation"],
    capture_output=True,
)
check("Package builds", result.returncode == 0)

result = subprocess.run(["actionscope", "--version"], capture_output=True, text=True)
check("CLI responds", result.returncode == 0, result.stdout.strip())

result = subprocess.run(
    ["actionscope", "scan", ".", "--output-format", "json"],
    capture_output=True,
    text=True,
)
try:
    data = json.loads(result.stdout)
    check(
        "Self-scan produces valid JSON",
        True,
        f"overall_risk: {data.get('overall_risk')}",
    )
except Exception:
    check(
        "Self-scan produces valid JSON",
        False,
        result.stderr[:100] if result.stderr else "no output",
    )

readme = open("README.md").read()
check("README has pip install", "pip install actionscope" in readme)
check("README has GitHub Action example", "uses:" in readme)

community_files = [
    "CITATION.cff",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "SECURITY.md",
    "SUPPORT.md",
]
missing_community_files = [path for path in community_files if not Path(path).is_file()]
check(
    "Community health files present",
    not missing_community_files,
    ", ".join(missing_community_files) if missing_community_files else "all present",
)

try:
    citation = yaml.safe_load(Path("CITATION.cff").read_text(encoding="utf-8"))
except (OSError, yaml.YAMLError) as exc:
    check("Citation metadata valid", False, str(exc))
else:
    citation_version = str(citation.get("version", ""))
    check(
        "Citation metadata valid",
        citation.get("cff-version") == "1.2.0"
        and citation.get("repository-code") == "https://github.com/r12habh/ActionScope"
        and citation_version == __version__,
        f"software version: {citation_version or 'missing'}",
    )

print(f"\n{'Ready to release!' if all(checks) else 'Fix issues before releasing.'}")
sys.exit(0 if all(checks) else 1)
