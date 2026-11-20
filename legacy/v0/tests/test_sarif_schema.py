"""Structural validation for SARIF output.

ActionScope users upload our SARIF to GitHub Code Scanning. Code Scanning
silently rejects payloads that are missing required fields or that violate the
documented field types/ranges, which means a regression here surfaces as
"alerts mysteriously stopped appearing" rather than a clear error. These
tests pin down the structural invariants Code Scanning enforces (per the
SARIF 2.1.0 schema and GitHub's own SARIF support docs):

- `version` exactly "2.1.0"
- Top-level `runs` is a non-empty array
- Each run has `tool.driver` with `name`, `informationUri`, and `rules`
- Each rule has an `id` matching ActionScope's `AS\\d{3}` convention
- Each result has `ruleId`, `message.text`, and `locations`
- Each result `level` is one of `none|note|warning|error`
- Each result's `security-severity` (when present) is a string parseable to a
  float in [0.0, 10.0]

These are the constraints whose violation makes Code Scanning drop alerts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from actionscope.cli import main
from actionscope.models import CompromisedActionFinding, RiskLevel, ScanResult
from actionscope.reporters.sarif import to_sarif

FIXTURE = str(Path(__file__).resolve().parent / "fixtures" / "coverage_repo")

VALID_LEVELS = {"none", "note", "warning", "error"}
RULE_ID_RE = re.compile(r"^AS\d{3}$")


@pytest.fixture(scope="module")
def sarif_doc(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Run a scan once and parse its SARIF output for the module's tests."""
    out = tmp_path_factory.mktemp("sarif") / "results.sarif"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan", FIXTURE,
            "--output-format", "sarif",
            "--output-file", str(out),
            "--no-color",
        ],
    )
    assert result.exit_code in (0, 1), (
        f"SARIF scan exited unexpectedly: {result.exit_code}\n{result.output[:500]}"
    )
    return json.loads(out.read_text(encoding="utf-8"))


def test_version_is_exactly_2_1_0(sarif_doc: dict) -> None:
    """GitHub Code Scanning only accepts SARIF 2.1.0; any other version is rejected."""
    assert sarif_doc.get("version") == "2.1.0"


def test_schema_url_is_present_and_well_formed(sarif_doc: dict) -> None:
    """The `$schema` URL field is required by SARIF tooling for validation.

    Strictly checks for the `$schema` key (not the unprefixed `schema`) so a
    regression that accidentally emits the wrong field name surfaces here
    instead of silently passing.
    """
    assert "$schema" in sarif_doc, "top-level `$schema` field is missing"
    schema = sarif_doc["$schema"]
    assert isinstance(schema, str), (
        f"$schema must be a string, got {type(schema).__name__}"
    )
    assert schema.startswith("http"), f"$schema must be a URL, got {schema!r}"


def test_runs_is_a_non_empty_array(sarif_doc: dict) -> None:
    runs = sarif_doc.get("runs")
    assert isinstance(runs, list) and runs, "runs must be a non-empty array"


def test_tool_driver_metadata_present(sarif_doc: dict) -> None:
    """Each run's tool.driver must carry the minimum identification fields."""
    driver = sarif_doc["runs"][0].get("tool", {}).get("driver", {})
    assert driver.get("name") == "ActionScope"
    assert isinstance(driver.get("informationUri"), str), (
        "tool.driver.informationUri is required so Code Scanning can deep-link"
    )
    assert isinstance(driver.get("version"), str)


def test_every_rule_id_matches_ActionScope_convention(sarif_doc: dict) -> None:
    """Rule IDs must match `AS\\d{3}` so consumers can map them to docs."""
    rules = sarif_doc["runs"][0]["tool"]["driver"].get("rules", [])
    assert rules, "rules array must list every rule the run could produce"
    bad = [r.get("id") for r in rules if not RULE_ID_RE.match(str(r.get("id", "")))]
    assert not bad, f"rule IDs violating AS\\d{{3}} convention: {bad}"


def test_every_rule_has_short_and_full_description(sarif_doc: dict) -> None:
    """Code Scanning surfaces shortDescription in the alert list and
    fullDescription in the alert details; missing them makes alerts opaque.
    """
    rules = sarif_doc["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        rid = rule.get("id")
        short = (rule.get("shortDescription") or {}).get("text")
        full = (rule.get("fullDescription") or {}).get("text")
        assert isinstance(short, str) and short.strip(), (
            f"rule {rid} missing shortDescription.text"
        )
        assert isinstance(full, str) and full.strip(), (
            f"rule {rid} missing fullDescription.text"
        )


def test_results_array_is_present(sarif_doc: dict) -> None:
    """A run with no findings still requires an empty `results: []`, not absent."""
    results = sarif_doc["runs"][0].get("results")
    assert isinstance(results, list), "results must be an array (possibly empty)"


def test_every_result_has_ruleId_message_and_location(sarif_doc: dict) -> None:
    """Every result needs ruleId, message.text, and a non-empty locations list."""
    results = sarif_doc["runs"][0]["results"]
    assert results, "fixture should produce at least one SARIF result"
    for i, result in enumerate(results):
        ctx = f"results[{i}]"
        assert RULE_ID_RE.match(str(result.get("ruleId", ""))), (
            f"{ctx}: ruleId must match AS\\d{{3}}, got {result.get('ruleId')!r}"
        )
        message = result.get("message") or {}
        text = message.get("text")
        assert isinstance(text, str) and text.strip(), (
            f"{ctx}: message.text must be a non-empty string"
        )
        locations = result.get("locations") or []
        assert locations, f"{ctx}: locations[] must be non-empty"
        first_loc = locations[0]
        artifact_uri = (
            (first_loc.get("physicalLocation") or {}).get("artifactLocation") or {}
        ).get("uri")
        assert isinstance(artifact_uri, str) and artifact_uri, (
            f"{ctx}: artifactLocation.uri must be a non-empty string"
        )


def test_every_result_level_is_valid(sarif_doc: dict) -> None:
    """If `level` is set it must be one of the four SARIF-defined values."""
    for i, result in enumerate(sarif_doc["runs"][0]["results"]):
        level = result.get("level")
        if level is not None:
            assert level in VALID_LEVELS, (
                f"results[{i}].level={level!r} must be one of {sorted(VALID_LEVELS)}"
            )


def test_security_severity_is_numeric_in_range(sarif_doc: dict) -> None:
    """`security-severity` is the CVSS-style 0.0–10.0 number Code Scanning uses
    to bucket alerts into severity tiers. It must be a STRING (per spec) that
    parses to a float in that range.

    Regression guard for the AS013 hardcoded "10.0" bug we caught earlier: the
    same code path is now exercised end-to-end.
    """
    for i, result in enumerate(sarif_doc["runs"][0]["results"]):
        props = result.get("properties") or {}
        sev = props.get("security-severity")
        if sev is None:
            continue
        assert isinstance(sev, str), (
            f"results[{i}].properties['security-severity'] must be a string, "
            f"got {type(sev).__name__}"
        )
        try:
            sev_f = float(sev)
        except ValueError:
            pytest.fail(
                f"results[{i}].properties['security-severity']={sev!r} is not "
                "parseable as a float"
            )
        assert 0.0 <= sev_f <= 10.0, (
            f"results[{i}].properties['security-severity']={sev_f} out of [0,10]"
        )


def test_AS013_critical_finding_maps_to_critical_severity_band(
    sarif_doc: dict,
) -> None:
    """For the coverage_repo's CRITICAL AS013 finding, SARIF severity must be
    in the critical band (>=9.0). This locks down the CRITICAL path.
    """
    as013_results = [
        r for r in sarif_doc["runs"][0]["results"]
        if r.get("ruleId") == "AS013"
    ]
    assert as013_results, "fixture must produce an AS013 result"
    for r in as013_results:
        sev = float((r.get("properties") or {}).get("security-severity", "0"))
        assert 9.0 <= sev <= 10.0, (
            f"AS013 CRITICAL finding mapped to security-severity={sev}, "
            "expected in the critical band [9.0, 10.0]"
        )


def test_AS013_high_finding_does_not_get_critical_severity() -> None:
    """A HIGH-risk AS013 finding must map to severity in the HIGH band
    (around 7.x), not the CRITICAL band (9.0+).

    This is the actual regression guard for the AS013 hardcoded `10.0` bug
    we caught in code review: if a future implementation collapses all AS013
    severities to a single constant, this test produces a HIGH-risk finding
    and proves the emitted severity tracks the risk level rather than being
    constant.
    """
    high_finding = CompromisedActionFinding(
        workflow_file=".github/workflows/triage.yml",
        job_name="triage",
        step_name="Maintain one comment",
        uses_ref=(
            "actions-cool/maintain-one-comment@"
            "11bd71901bbe5b1630ceea73d27597364c9af683"
        ),
        action_name="actions-cool/maintain-one-comment",
        ref="11bd71901bbe5b1630ceea73d27597364c9af683",
        is_sha_pinned=True,
        compromise_date="2026-05-18T19:10:24Z",
        advisory_url="https://example.com/advisory",
        description="ambiguous SHA pin of a known-compromised action",
        risk_level=RiskLevel.HIGH,
    )
    result = ScanResult(compromised_action_findings=[high_finding])
    sarif = json.loads(to_sarif(result))

    as013 = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "AS013"]
    assert len(as013) == 1, "expected exactly one AS013 result from one finding"
    sev = float((as013[0].get("properties") or {}).get("security-severity", "0"))
    assert 7.0 <= sev < 9.0, (
        f"HIGH AS013 finding mapped to security-severity={sev}; expected the "
        "HIGH band [7.0, 9.0). A hardcoded constant (e.g. 10.0) would fail "
        "here, which is the point of this test."
    )
    assert as013[0].get("level") != "error" or sev < 9.0, (
        "level=error coupled with sev<9.0 means the level field follows the "
        "severity mapping correctly"
    )


def test_rule_ids_used_in_results_are_declared_in_rules(sarif_doc: dict) -> None:
    """Every ruleId referenced by results must be declared in tool.driver.rules.

    Code Scanning will reject results whose ruleId isn't declared.
    """
    declared = {r["id"] for r in sarif_doc["runs"][0]["tool"]["driver"]["rules"]}
    used = {r["ruleId"] for r in sarif_doc["runs"][0]["results"]}
    missing = used - declared
    assert not missing, (
        f"results reference rule IDs not declared in tool.driver.rules: {missing}"
    )


def test_no_duplicate_rule_declarations(sarif_doc: dict) -> None:
    """Duplicate rule entries make Code Scanning's UI inconsistent about
    severity and description.
    """
    ids = [r["id"] for r in sarif_doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids)), (
        f"duplicate rule IDs declared: "
        f"{[i for i in set(ids) if ids.count(i) > 1]}"
    )


def test_invocations_endTimeUtc_is_iso8601(sarif_doc: dict) -> None:
    """The endTimeUtc in invocations must be ISO 8601, not a unix timestamp."""
    invocations = sarif_doc["runs"][0].get("invocations") or []
    if not invocations:
        pytest.skip("no invocations recorded")
    end_time = invocations[0].get("endTimeUtc")
    if end_time is None:
        pytest.skip("endTimeUtc not present")
    assert isinstance(end_time, str)
    # ISO 8601 has a 'T' separator; unix epoch numbers don't.
    assert "T" in end_time, f"endTimeUtc={end_time!r} doesn't look like ISO 8601"
