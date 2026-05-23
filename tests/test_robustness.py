"""Robustness tests for malformed and adversarial input.

ActionScope runs on user repositories that may contain malformed YAML,
unicode in step names, zero-byte files, broken symlinks, files behind
permission errors, or .github/workflows directories that don't exist.
Every one of these is a path where a bug surfaces as a scanner crash —
which is worse than a missed finding, because users learn to distrust the
tool entirely.

These tests assert that the CLI exits cleanly (code 0 or 1, never crashes
with an uncaught exception) and that the JSON output remains structurally
valid even when inputs are pathological.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from actionscope.cli import main


def _scan(repo: Path) -> tuple[int, dict | None, str]:
    """Run a JSON scan on `repo`; return (exit_code, parsed_json_or_None, trailing).

    The CLI currently emits warning lines to stdout after the JSON document
    when files fail to parse. We tolerate this here by using `raw_decode` to
    take only the leading JSON value and treat anything after it as trailing
    log output. (See follow-up: warnings should go to stderr.)
    """
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", str(repo), "--output-format", "json", "--no-color"]
    )
    data: dict | None = None
    trailing = ""
    if result.output:
        try:
            value, idx = json.JSONDecoder().raw_decode(result.output)
            data = value if isinstance(value, dict) else None
            trailing = result.output[idx:].strip()
        except json.JSONDecodeError:
            data = None
            trailing = result.output
    return result.exit_code, data, trailing


def _make_workflow(repo: Path, name: str, content: str) -> Path:
    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    wf_path = wf_dir / name
    wf_path.write_text(content, encoding="utf-8")
    return wf_path


def test_empty_repo_does_not_crash(tmp_path: Path) -> None:
    """A directory with no .github/workflows/ must not crash the scanner."""
    code, _data, _ = _scan(tmp_path)
    assert code == 0


def test_empty_workflows_directory_does_not_crash(tmp_path: Path) -> None:
    """An empty .github/workflows/ must not crash the scanner."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    code, _, _ = _scan(tmp_path)
    assert code == 0


def test_zero_byte_workflow_file_is_handled(tmp_path: Path) -> None:
    """A zero-byte .yml file must be skipped, not crash, and not be counted."""
    _make_workflow(tmp_path, "empty.yml", "")
    code, data, _ = _scan(tmp_path)
    assert code == 0
    assert data is not None


def test_malformed_yaml_workflow_reports_error_but_continues(tmp_path: Path) -> None:
    """A workflow with broken YAML must be reported as an error, not crash.

    A second valid workflow in the same repo must still be scanned.
    """
    _make_workflow(
        tmp_path, "broken.yml", "name: Broken\non: [push\njobs:\n  : invalid\n"
    )
    _make_workflow(
        tmp_path,
        "good.yml",
        "name: Good\non: [push]\njobs:\n  ok:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
    )

    code, data, _ = _scan(tmp_path)

    assert code == 0
    assert data is not None
    # At least one error must be reported, naming the broken file.
    errors = data.get("errors") or []
    assert any("broken.yml" in str(e) for e in errors), (
        f"expected an error for broken.yml; got: {errors!r}"
    )
    # The valid workflow still gets counted.
    assert data["workflow_count"] >= 1


def test_unicode_in_workflow_does_not_crash(tmp_path: Path) -> None:
    """Step names with emoji and CJK characters must round-trip through the scanner."""
    _make_workflow(
        tmp_path,
        "unicode.yml",
        (
            "name: 测试 Workflow 🚀\n"
            "on: [push]\n"
            "jobs:\n"
            "  '日本語ジョブ':\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: 🎯 Checkout\n"
            "        uses: actions/checkout@v4\n"
        ),
    )

    code, data, _ = _scan(tmp_path)
    assert code == 0
    assert data is not None
    assert data["workflow_count"] == 1
    # The unpinned `actions/checkout@v4` should still be picked up.
    assert any(
        f["uses"] == "actions/checkout@v4" for f in data.get("unpinned_actions", [])
    )


def test_non_utf8_workflow_file_is_reported_as_error(tmp_path: Path) -> None:
    """A workflow saved with Latin-1 bytes must surface as a read error, not crash."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    # 0xff is invalid as the first byte of a UTF-8 stream.
    (wf_dir / "latin1.yml").write_bytes(b"name: \xff Latin\non: [push]\n")

    code, data, _ = _scan(tmp_path)
    assert code == 0
    assert data is not None
    errors = data.get("errors") or []
    assert any("latin1.yml" in str(e) for e in errors), (
        f"expected an encoding error for latin1.yml; got: {errors!r}"
    )


def test_workflows_dir_with_non_yaml_files_is_handled(tmp_path: Path) -> None:
    """Non-YAML files in .github/workflows/ must be ignored, not parsed as workflows."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "README.md").write_text("# notes\n", encoding="utf-8")
    (wf_dir / ".keep").write_text("", encoding="utf-8")
    (wf_dir / "config.toml").write_text("[x]\nk=1\n", encoding="utf-8")

    code, data, _ = _scan(tmp_path)
    assert code == 0
    assert data is not None
    assert data["workflow_count"] == 0


def test_workflow_with_no_steps_is_handled(tmp_path: Path) -> None:
    """A workflow with a job that has zero steps must not crash any analyzer."""
    _make_workflow(
        tmp_path,
        "no-steps.yml",
        (
            "name: No Steps\n"
            "on: [push]\n"
            "jobs:\n"
            "  empty:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps: []\n"
        ),
    )

    code, data, _ = _scan(tmp_path)
    assert code == 0
    assert data is not None
    # A workflow with zero steps produces no findings, so workflow_count
    # (= workflows with findings) remains 0. The point of this test is that
    # the analyzers do not crash on the empty steps list.
    assert data["summary"]["credential_sources"] == 0
    assert (data.get("errors") or []) == []


def test_workflow_with_only_uses_no_run_is_handled(tmp_path: Path) -> None:
    """Steps that only have `uses:` (no `run:`) must not trip the injection detector."""
    _make_workflow(
        tmp_path,
        "uses-only.yml",
        (
            "name: Uses Only\n"
            "on: [pull_request_target]\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  check:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        ),
    )

    code, data, _ = _scan(tmp_path)
    assert code == 0
    assert data is not None
    # No `run:` block means no script-injection finding.
    assert data["summary"]["script_injection_risks"] == 0


def test_workflow_with_yaml_anchors_is_parsed(tmp_path: Path) -> None:
    """YAML anchors/aliases are valid and must not crash the workflow loader."""
    _make_workflow(
        tmp_path,
        "anchors.yml",
        (
            "name: Anchors\n"
            "on: [push]\n"
            "defaults: &defaults\n"
            "  shell: bash\n"
            "jobs:\n"
            "  a:\n"
            "    runs-on: ubuntu-latest\n"
            "    defaults:\n"
            "      run:\n"
            "        <<: *defaults\n"
            "    steps:\n"
            "      - run: echo hello\n"
        ),
    )

    code, _data, _ = _scan(tmp_path)
    assert code == 0


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX-only: chmod is the cross-fs permission gate"
)
def test_permission_error_on_workflow_file_is_reported(tmp_path: Path) -> None:
    """A workflow file with mode 000 must surface as a read error, not crash."""
    wf = _make_workflow(
        tmp_path,
        "locked.yml",
        "name: x\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
    )
    try:
        wf.chmod(0o000)
        code, data, _ = _scan(tmp_path)
        assert code == 0
        assert data is not None
        errors = data.get("errors") or []
        # Skip the assertion when running as root, which bypasses chmod
        # permission checks entirely.
        if os.geteuid() != 0:
            assert any("locked.yml" in str(e) for e in errors), (
                f"expected a permission error for locked.yml; got: {errors!r}"
            )
    finally:
        wf.chmod(0o644)


def test_broken_symlink_in_workflows_dir_is_handled(tmp_path: Path) -> None:
    """A symlink pointing nowhere must not crash the scanner."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    broken_link = wf_dir / "ghost.yml"
    broken_link.symlink_to(tmp_path / "does-not-exist.yml")

    code, _data, _ = _scan(tmp_path)
    assert code == 0


def test_scan_path_that_does_not_exist_exits_cleanly(tmp_path: Path) -> None:
    """`actionscope scan /no/such/path` must exit with a non-traceback message."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path / "absent")])
    # Either exit 0 with a "no workflows" message, or exit non-zero with a
    # readable error — but never a traceback.
    assert "Traceback" not in result.output, (
        f"CLI should not surface a traceback; got:\n{result.output}"
    )


def test_scan_path_is_a_file_not_a_directory(tmp_path: Path) -> None:
    """Passing a single workflow file (not a directory) is supported.

    `find_workflow_files()` explicitly accepts a `.yml`/`.yaml` file path, so
    the scan must succeed and report the file's content, not silently fall
    back to "0 workflows" or exit non-zero.
    """
    wf = _make_workflow(
        tmp_path,
        "single.yml",
        (
            "name: Single\n"
            "on: [push]\n"
            "jobs:\n"
            "  a:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        ),
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", str(wf), "--output-format", "json", "--no-color"]
    )

    assert "Traceback" not in result.output
    assert result.exit_code == 0
    data, _ = json.JSONDecoder().raw_decode(result.output)
    # actions/checkout@v4 is unpinned, so the file produces at least one
    # finding and thus increments workflow_count.
    assert data["workflow_count"] == 1
    assert any(
        f["uses"] == "actions/checkout@v4"
        for f in data.get("unpinned_actions", [])
    )


@pytest.mark.xfail(
    reason=(
        "CLI currently emits 'Warning: Could not parse workflow file ...' "
        "lines to stdout *after* the JSON payload when a workflow fails to "
        "parse, which breaks any downstream `json.loads`. Tests in this file "
        "work around it with raw_decode. This xfail tracks the desired future "
        "behavior — warnings should go to stderr in JSON output mode. When "
        "the CLI is fixed, this test starts XPASSing and the raw_decode "
        "workaround in `_scan` can be removed."
    ),
    strict=False,
)
def test_json_output_is_pure_json_when_files_fail_to_parse(tmp_path: Path) -> None:
    """Goal post: `json.loads(result.output)` succeeds even with parse errors."""
    _make_workflow(tmp_path, "broken.yml", "name: x\non: [push\njobs:\n  : invalid\n")
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", str(tmp_path), "--output-format", "json", "--no-color"]
    )
    # The full output should parse as one JSON document, with no trailing text.
    json.loads(result.output)


def test_yaml_with_extremely_long_step_name_is_handled(tmp_path: Path) -> None:
    """Long step names must not exhaust memory or cause catastrophic backtracking."""
    long_name = "A" * 8192
    _make_workflow(
        tmp_path,
        "long.yml",
        (
            f"name: Long\n"
            f"on: [push]\n"
            f"jobs:\n"
            f"  a:\n"
            f"    runs-on: ubuntu-latest\n"
            f"    steps:\n"
            f"      - name: {long_name}\n"
            f"        run: echo done\n"
        ),
    )

    code, _data, _ = _scan(tmp_path)
    assert code == 0
