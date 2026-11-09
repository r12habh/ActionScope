"""Reproduce the synthetic offline reference; never call AWS or run workflows."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from click.testing import CliRunner

from actionscope.cli import main


def evaluate() -> dict:
    root = Path(__file__).resolve().parents[1]
    example = root / "examples/offline-iam-evidence"
    snapshot = example / "synthetic-iam.json"
    mapping = example / "synthetic-role-map.json"
    scenarios = {
        "original_workflow": [],
        "owner_mapping": ["--iam-snapshot", str(snapshot), "--role-map", str(mapping)],
        "potential_trust": [
            "--iam-snapshot",
            str(snapshot),
            "--github-repo",
            "example/app",
        ],
    }
    observations = {}
    for name, flags in scenarios.items():
        result = CliRunner().invoke(
            main,
            [
                "scan",
                str(example),
                "--offline",
                "--output-format",
                "json",
                *flags,
            ],
        )
        if result.exit_code:
            raise RuntimeError(result.output)
        data = json.loads(result.stdout)
        observations[name] = {
            "bindings": len(data["findings"]),
            "policy_matches": data["summary"]["policies_found"],
            "candidate_policy_matches": data["summary"]["candidate_policies_found"],
            "resolutions": [f["role_resolution"] for f in data["findings"]],
            "coverage": data["coverage_status"],
        }
    assert observations["original_workflow"]["policy_matches"] == 0
    assert observations["owner_mapping"]["resolutions"] == ["owner_mapping"]
    assert observations["owner_mapping"]["policy_matches"] == 1
    assert observations["potential_trust"]["policy_matches"] == 0
    assert observations["potential_trust"]["candidate_policy_matches"] == 1
    assert observations["potential_trust"]["resolutions"] == [
        "workflow",
        "trust_candidate",
    ]
    assert all(item["coverage"] == "partial" for item in observations.values())
    return {
        "scope": "synthetic reference, not live AWS or external-use validation",
        "inputs_sha256": {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (snapshot, mapping, example / ".github/workflows/deploy.yml")
        },
        "observations": observations,
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
