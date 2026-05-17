"""End-to-end CLI integration tests against the demo_repo fixture."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from click.testing import CliRunner

from actionscope.cli import main


class TestDemoRepoScan:
    DEMO_REPO = str(Path(__file__).resolve().parent / "fixtures" / "demo_repo")

    def test_full_scan_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", self.DEMO_REPO])
        assert result.exit_code == 0

    def test_json_output_is_valid(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--output-format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "overall_risk" in data
        assert "findings" in data

    def test_detects_two_credential_sources(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--output-format", "json"],
        )
        data = json.loads(result.output)
        assert data["summary"]["credential_sources"] == 2

    def test_detects_passrole(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--output-format", "json"],
        )
        data = json.loads(result.output)
        findings_with_passrole = [
            f for f in data["findings"] if f.get("has_passrole")
        ]
        assert len(findings_with_passrole) >= 1

    def test_fail_on_critical_exits_one(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--fail-on", "critical"],
        )
        assert result.exit_code == 1

    def test_fail_on_low_exits_one_if_any_findings(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--fail-on", "low"],
        )
        assert result.exit_code == 1

    def test_markdown_output_contains_headers(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--output-format", "markdown"],
        )
        assert "ActionScope" in result.output
        assert "##" in result.output
        assert (
            "PassRole" in result.output
            or "passrole" in result.output.lower()
        )

    def test_test_workflow_no_aws_not_in_findings(self) -> None:
        """test.yml has no AWS access — should not appear as credential source."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--output-format", "json"],
        )
        data = json.loads(result.output)
        workflow_files = [f["workflow_file"] for f in data["findings"]]
        assert not any("test.yml" in wf for wf in workflow_files)

    def test_write_all_permissions_detected(self) -> None:
        """release.yml has write-all — should appear in github_token_permissions."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--output-format", "json"],
        )
        data = json.loads(result.output)
        assert len(data["github_token_permissions"]) > 0

    def test_unpinned_actions_detected(self) -> None:
        """demo_repo uses floating action tags, which should be reported."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--output-format", "json"],
        )
        data = json.loads(result.output)

        assert data["summary"]["unpinned_actions"] >= 1
        assert any(
            finding["uses"] == "actions/checkout@v4"
            for finding in data["unpinned_actions"]
        )

    def test_sarif_output_is_valid_and_has_results(self) -> None:
        """SARIF output should be consumable by GitHub Code Scanning."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", self.DEMO_REPO, "--output-format", "sarif"],
        )
        data = json.loads(result.output)

        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0

    def test_no_aws_repo_exits_cleanly(self) -> None:
        """A repo with no workflows should exit 0 with no-AWS message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            result = runner.invoke(main, ["scan", tmpdir])
            assert result.exit_code == 0
