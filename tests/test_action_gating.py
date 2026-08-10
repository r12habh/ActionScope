"""Static regression tests for Marketplace Action gating behavior."""

from __future__ import annotations

from pathlib import Path

import yaml

ACTION_FILE = Path(__file__).parents[1] / "action.yml"


def _action() -> dict:
    return yaml.safe_load(ACTION_FILE.read_text(encoding="utf-8"))


def test_marketplace_action_is_report_only_by_default() -> None:
    assert _action()["inputs"]["fail-on"]["default"] == ""


def test_action_exposes_confidence_and_new_only_inputs() -> None:
    inputs = _action()["inputs"]

    assert inputs["new-only"]["default"] == "false"
    assert inputs["min-confidence"]["default"] == "high"
    assert inputs["require-baseline"]["default"] == "false"


def test_action_exposes_custom_risk_policy_input() -> None:
    inputs = _action()["inputs"]
    text = ACTION_FILE.read_text(encoding="utf-8")

    assert inputs["config"]["default"] == ""
    assert 'SCAN_FLAGS+=(--config "$INPUT_CONFIG")' in text


def test_action_uses_cache_for_cross_run_baseline() -> None:
    text = ACTION_FILE.read_text(encoding="utf-8")

    assert "actions/cache/restore@" in text
    assert "actions/cache/save@" in text
    assert "actions/download-artifact@" not in text
    assert "actions/upload-artifact@" not in text


def test_action_clears_workspace_state_and_requires_a_cache_match() -> None:
    text = ACTION_FILE.read_text(encoding="utf-8")

    clear = text.index("rm -f .actionscope/last_scan.json")
    restore = text.index("uses: actions/cache/restore@")
    assert clear < restore
    assert "steps.restore-pr.outputs.cache-matched-key" in text
    assert "steps.restore-branch.outputs.cache-matched-key" in text
    assert "github.event_name == 'pull_request_target'" in text
    pr_restore = text.split(
        "- name: Restore exact default-branch state for pull request",
        1,
    )[1].split(
        "- name: Restore previous state for trusted branch run",
        1,
    )[0]
    assert "restore-keys:" not in pr_restore
    assert 'if [ -z "$RESTORED_KEY" ]' in text


def test_action_scans_once_and_uses_gate_command() -> None:
    text = ACTION_FILE.read_text(encoding="utf-8")

    assert text.count('actionscope scan "$INPUT_PATH"') == 1
    assert "actionscope gate /tmp/actionscope-results.json" in text
    assert "RISK_ORDER" not in text


def test_action_preserves_hard_block_report_before_failing_policy() -> None:
    text = ACTION_FILE.read_text(encoding="utf-8")

    assert 'SCAN_EXIT=$?' in text
    assert '[ "$SCAN_EXIT" -gt 1 ]' in text
    assert "d.get('gate', {}).get('exit_code', 0)" in text
    assert "steps.scan.outputs.gate-exit-code != '0'" in text


def test_action_surfaces_report_generation_failures() -> None:
    text = ACTION_FILE.read_text(encoding="utf-8")

    assert 'failed to render $INPUT_OUTPUT_FORMAT report' in text
    assert "failed to render SARIF report" in text
    assert "failed to render the PR comment" in text
    assert '--format "$INPUT_OUTPUT_FORMAT" || true' not in text
    assert "--format markdown 2>/dev/null" not in text


def test_action_only_saves_baseline_on_default_branch_push() -> None:
    text = ACTION_FILE.read_text(encoding="utf-8")

    assert "github.event_name == 'push'" in text
    assert "github.ref_name == github.event.repository.default_branch" in text


def test_action_run_scripts_do_not_interpolate_expressions_directly() -> None:
    action = _action()
    run_scripts = [
        step["run"]
        for step in action["runs"]["steps"]
        if isinstance(step, dict) and isinstance(step.get("run"), str)
    ]

    assert all("${{ inputs." not in script for script in run_scripts)
    assert all("${{ github." not in script for script in run_scripts)
