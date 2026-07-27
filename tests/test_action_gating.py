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


def test_action_uses_cache_for_cross_run_baseline() -> None:
    text = ACTION_FILE.read_text(encoding="utf-8")

    assert "actions/cache/restore@" in text
    assert "actions/cache/save@" in text
    assert "actions/download-artifact@" not in text
    assert "actions/upload-artifact@" not in text


def test_action_scans_once_and_uses_gate_command() -> None:
    text = ACTION_FILE.read_text(encoding="utf-8")

    assert text.count('actionscope scan "$INPUT_PATH"') == 1
    assert "actionscope gate /tmp/actionscope-results.json" in text
    assert "RISK_ORDER" not in text


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
