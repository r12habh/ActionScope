"""Tests for known-compromised GitHub Actions detection."""

from __future__ import annotations

from pathlib import Path
from shutil import copyfile

from actionscope.analyzers.compromised_actions import (
    check_workflow_for_compromised_actions,
    is_compromised_ref,
    load_compromised_actions,
    scan_for_compromised_actions,
)
from actionscope.models import RiskLevel
from actionscope.parsers.workflow import parse_workflow_file

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "workflows"
FULL_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def test_load_compromised_actions_returns_actions_dict() -> None:
    db = load_compromised_actions()

    assert isinstance(db, dict)
    assert "actions" in db


def test_is_compromised_ref_true_for_issues_helper_v3() -> None:
    compromised, _entry = is_compromised_ref(
        "actions-cool/issues-helper",
        "v3",
        load_compromised_actions(),
    )

    assert compromised is True


def test_is_compromised_ref_true_for_specific_issues_helper_version() -> None:
    compromised, _entry = is_compromised_ref(
        "actions-cool/issues-helper",
        "v3.7.4",
        load_compromised_actions(),
    )

    assert compromised is True


def test_is_compromised_ref_false_for_unknown_sha() -> None:
    compromised, entry = is_compromised_ref(
        "actions-cool/issues-helper",
        FULL_SHA,
        load_compromised_actions(),
    )

    assert compromised is False
    assert entry is None


def test_is_compromised_ref_false_for_unrelated_action() -> None:
    compromised, entry = is_compromised_ref(
        "actions/checkout",
        "v4",
        load_compromised_actions(),
    )

    assert compromised is False
    assert entry is None


def test_is_compromised_ref_case_insensitive_action_name() -> None:
    compromised, _entry = is_compromised_ref(
        "Actions-Cool/Issues-Helper",
        "v3",
        load_compromised_actions(),
    )

    assert compromised is True


def test_check_workflow_for_compromised_actions_finds_fixture() -> None:
    workflow = parse_workflow_file(str(FIXTURE_DIR / "compromised_action.yml"))
    assert workflow is not None

    findings = check_workflow_for_compromised_actions(
        workflow,
        "compromised_action.yml",
        load_compromised_actions(),
    )

    assert {finding.action_name for finding in findings} == {
        "actions-cool/issues-helper",
        "actions-cool/maintain-one-comment",
    }


def test_compromised_action_finding_risk_is_critical_for_tag() -> None:
    workflow = {
        "jobs": {
            "triage": {
                "steps": [{"uses": "actions-cool/issues-helper@v3"}],
            }
        }
    }

    findings = check_workflow_for_compromised_actions(
        workflow,
        "workflow.yml",
        load_compromised_actions(),
    )

    assert findings[0].risk_level is RiskLevel.CRITICAL


def test_scan_for_compromised_actions_empty_for_clean_repo(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    copyfile(FIXTURE_DIR / "no_aws.yml", workflow_dir / "no_aws.yml")

    findings, errors = scan_for_compromised_actions(str(tmp_path))

    assert findings == []
    assert errors == []


def test_compromised_action_advisory_url_is_non_empty() -> None:
    workflow = {
        "jobs": {
            "triage": {"steps": [{"uses": "actions-cool/issues-helper@v3"}]},
        }
    }

    findings = check_workflow_for_compromised_actions(
        workflow,
        "workflow.yml",
        load_compromised_actions(),
    )

    assert findings[0].advisory_url


def test_compromised_action_description_is_non_empty() -> None:
    workflow = {
        "jobs": {
            "triage": {"steps": [{"uses": "actions-cool/issues-helper@v3"}]},
        }
    }

    findings = check_workflow_for_compromised_actions(
        workflow,
        "workflow.yml",
        load_compromised_actions(),
    )

    assert findings[0].description


def test_workflow_scan_unknown_sha_produces_no_finding_when_refs_explicit() -> None:
    """SHA pins not in the explicit affected_refs list must not produce findings."""
    workflow = {
        "jobs": {
            "triage": {
                "steps": [
                    {"uses": f"actions-cool/issues-helper@{FULL_SHA}"},
                ],
            }
        }
    }

    findings = check_workflow_for_compromised_actions(
        workflow,
        "workflow.yml",
        load_compromised_actions(),
    )

    assert findings == []


def test_sha_pinned_action_with_no_known_bad_sha_produces_no_finding() -> None:
    workflow = {
        "jobs": {
            "triage": {
                "steps": [
                    {"uses": f"actions-cool/maintain-one-comment@{FULL_SHA}"},
                ],
            }
        }
    }

    findings = check_workflow_for_compromised_actions(
        workflow,
        "workflow.yml",
        load_compromised_actions(),
    )

    assert findings == []


PROWLER_TJ_ACTIONS_SHA = "9426d40962ed5378910ee2e21d5f8c6fcbf2dd96"
TJ_ACTIONS_MALICIOUS_SHA = "0e58ed867288e6711d10da9293b8db84f3f3ed85"


def test_sha_pin_outside_malicious_shas_list_is_safe() -> None:
    """Regression: SHA pins to tj-actions/changed-files that are NOT the known
    malicious commit must not produce a finding.

    Both Prowler and Argo CD pin to `9426d40962ed5378910ee2e21d5f8c6fcbf2dd96`.
    The documented malicious commit is `0e58ed867288e6711d10da9293b8db84f3f3ed85`
    (per https://github.com/advisories/GHSA-mrrh-fwg8-r2c3 and the StepSecurity
    disclosure). The previous DB entry had empty affected_refs, which caused
    all SHA pins to be flagged HIGH — producing 41 false positives in the
    live scan of prowler-cloud/prowler and 1 in argoproj/argo-cd.
    """
    workflow = {
        "jobs": {
            "ci": {
                "steps": [
                    {"uses": f"tj-actions/changed-files@{PROWLER_TJ_ACTIONS_SHA}"},
                ],
            }
        }
    }

    findings = check_workflow_for_compromised_actions(
        workflow,
        "workflow.yml",
        load_compromised_actions(),
    )

    assert findings == [], (
        f"expected no finding for non-malicious SHA pin, got {len(findings)}"
    )


def test_sha_pin_matching_malicious_shas_list_is_flagged() -> None:
    """Pinning to the documented malicious commit of tj-actions/changed-files
    must still produce a finding."""
    workflow = {
        "jobs": {
            "ci": {
                "steps": [
                    {"uses": f"tj-actions/changed-files@{TJ_ACTIONS_MALICIOUS_SHA}"},
                ],
            }
        }
    }

    findings = check_workflow_for_compromised_actions(
        workflow,
        "workflow.yml",
        load_compromised_actions(),
    )

    assert len(findings) == 1
    assert findings[0].is_sha_pinned is True
    assert findings[0].action_name == "tj-actions/changed-files"


def test_tag_pin_of_action_with_malicious_shas_still_flagged() -> None:
    """Adding `malicious_shas` to a compromised action entry must NOT silence
    tag-pin detection — tags are still mutable and historically affected."""
    workflow = {
        "jobs": {
            "ci": {
                "steps": [
                    {"uses": "tj-actions/changed-files@v45"},
                ],
            }
        }
    }

    findings = check_workflow_for_compromised_actions(
        workflow,
        "workflow.yml",
        load_compromised_actions(),
    )

    assert len(findings) == 1
    assert findings[0].is_sha_pinned is False
