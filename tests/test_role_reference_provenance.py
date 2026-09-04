"""Tests for preserving dynamic role-reference provenance in reports."""

import io

from rich.console import Console

from actionscope.analyzers.risk_engine import build_bindings
from actionscope.coverage import build_coverage_gaps
from actionscope.models import ScanResult
from actionscope.parsers.workflow import (
    classify_role_reference,
    extract_aws_credential_sources,
)
from actionscope.reporters.json_reporter import to_json
from actionscope.reporters.terminal import render_scan_result


def _workflow(role_reference: str) -> dict:
    return {
        "permissions": {"id-token": "write"},
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "uses": "aws-actions/configure-aws-credentials@v4",
                        "with": {"role-to-assume": role_reference},
                    }
                ],
            }
        },
    }


def test_classify_role_reference_literal_arn() -> None:
    assert (
        classify_role_reference("arn:aws:iam::123456789012:role/github-deploy-role")
        == "literal_arn"
    )


def test_classify_role_reference_literal_name() -> None:
    assert classify_role_reference("github-deploy-role") == "literal_name"


def test_classify_role_reference_secret() -> None:
    assert classify_role_reference("${{ secrets.DEPLOY_ROLE }}") == "secret"


def test_classify_role_reference_variable() -> None:
    assert classify_role_reference("${{ vars.DEPLOY_ROLE }}") == "variable"


def test_classify_role_reference_environment() -> None:
    assert classify_role_reference("${{ env.DEPLOY_ROLE }}") == "environment"


def test_classify_role_reference_input() -> None:
    assert classify_role_reference("${{ inputs.role-to-assume }}") == "input"


def test_classify_role_reference_other_expression() -> None:
    assert classify_role_reference("${{ github.repository }}-deploy") == "expression"


def test_extractor_records_role_reference_kind() -> None:
    source = extract_aws_credential_sources(
        _workflow("${{ vars.DEPLOY_ROLE }}"),
        ".github/workflows/deploy.yml",
    )[0]

    assert source.role_reference_kind == "variable"


def test_json_report_includes_role_reference_kind() -> None:
    source = extract_aws_credential_sources(
        _workflow("${{ secrets.DEPLOY_ROLE }}"),
        ".github/workflows/deploy.yml",
    )[0]
    binding = build_bindings([source], [], ".")[0]

    output = to_json(ScanResult(credential_sources=[source], bindings=[binding]))

    assert '"role_reference_kind": "secret"' in output


def test_coverage_gap_names_dynamic_reference_kind() -> None:
    source = extract_aws_credential_sources(
        _workflow("${{ inputs.deploy-role }}"),
        ".github/workflows/deploy.yml",
    )[0]
    binding = build_bindings([source], [], ".")[0]

    gaps = build_coverage_gaps(ScanResult(bindings=[binding]))

    assert len(gaps) == 1
    assert "input-backed reference" in gaps[0].description


def test_terminal_report_names_dynamic_reference_kind() -> None:
    source = extract_aws_credential_sources(
        _workflow("${{ env.DEPLOY_ROLE }}"),
        ".github/workflows/deploy.yml",
    )[0]
    binding = build_bindings([source], [], ".")[0]
    stream = io.StringIO()

    render_scan_result(
        ScanResult(credential_sources=[source], bindings=[binding]),
        Console(file=stream, force_terminal=False, color_system=None),
    )

    assert "dynamic environment reference" in stream.getvalue()
