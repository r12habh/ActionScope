"""Non-AWS S3 endpoint regressions, including the Gitea R2 release pattern."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from actionscope.cli import main
from actionscope.parsers.credential_endpoints import uses_only_non_aws_s3
from actionscope.parsers.workflow import extract_aws_credential_sources, scan_workflows

FIXTURE = Path(__file__).parent / "fixtures" / "r2_repo"
R2_ENDPOINT = "https://account.r2.cloudflarestorage.com"
R2_RUN = (
    'aws s3 sync dist/release "s3://$BUCKET/releases" '
    '--endpoint-url "https://$ACCOUNT_ID.r2.cloudflarestorage.com" --no-progress'
)
KEY_ENV = {
    "AWS_ACCESS_KEY_ID": "${{ secrets.ACCESS_KEY }}",
    "AWS_SECRET_ACCESS_KEY": "${{ secrets.SECRET_KEY }}",
    "ACCOUNT_ID": "${{ secrets.ACCOUNT_ID }}",
    "BUCKET": "${{ secrets.BUCKET }}",
    "AWS_DEFAULT_REGION": "auto",
}


def _workflow(run: str = R2_RUN) -> dict:
    return {
        "on": "workflow_dispatch",
        "jobs": {
            "release": {
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "Upload", "run": run, "env": dict(KEY_ENV)}],
            }
        },
    }


@pytest.mark.parametrize(
    "run,env",
    [
        (R2_RUN, KEY_ENV),
        (f"aws s3 ls --endpoint-url={R2_ENDPOINT}", {}),
        (f"aws --endpoint-url {R2_ENDPOINT} s3api list-buckets", {}),
        (f"aws --region auto --endpoint-url {R2_ENDPOINT} s3 ls", {}),
        (f"/usr/local/bin/aws s3 ls --endpoint-url {R2_ENDPOINT}", {}),
        (f"aws s3 ls \\\n  --endpoint-url {R2_ENDPOINT}", {}),
        (f"aws s3 ls --endpoint-url {R2_ENDPOINT}\n" * 2, {}),
        (
            f"aws s3 ls --endpoint-url {R2_ENDPOINT} && "
            f"aws s3api list-buckets --endpoint-url {R2_ENDPOINT}",
            {},
        ),
        ("aws s3 ls", {"AWS_ENDPOINT_URL": R2_ENDPOINT}),
        ("aws s3 ls", {"AWS_ENDPOINT_URL_S3": R2_ENDPOINT}),
        ("aws s3 ls --endpoint-url $ENDPOINT", {"ENDPOINT": R2_ENDPOINT}),
        ("aws s3 ls --endpoint-url ${ENDPOINT}", {"ENDPOINT": R2_ENDPOINT}),
        ("aws s3 ls --endpoint-url https://account.eu.r2.cloudflarestorage.com", {}),
        (
            "aws s3 ls --endpoint-url "
            "https://${{ secrets.ACCOUNT }}.r2.cloudflarestorage.com",
            {},
        ),
        (
            f"aws s3 ls --endpoint-url {R2_ENDPOINT}",
            {
                "AWS_ENDPOINT_URL": "https://s3.amazonaws.com",
                "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true",
            },
        ),
    ],
)
def test_explicit_r2_endpoints_are_recognized(run: str, env: dict) -> None:
    assert uses_only_non_aws_s3(run, env)


@pytest.mark.parametrize(
    "run,env",
    [
        ("aws s3 ls", {}),
        ("aws s3 ls", {"AWS_DEFAULT_REGION": "auto"}),
        ("aws s3 ls", {"AWS_ACCESS_KEY_ID": "${{ secrets.CLOUDFLARE_R2_KEY }}"}),
        ("aws s3 ls --endpoint-url https://s3.amazonaws.com", {}),
        ("aws s3 ls --endpoint-url https://s3.us-east-1.amazonaws.com", {}),
        ("aws s3 ls --endpoint-url https://s3.internal.example", {}),
        (
            "aws s3 ls --endpoint-url https://account.r2.cloudflarestorage.com.evil.test",
            {},
        ),
        (
            "aws s3 ls --endpoint-url https://account.r2.cloudflarestorage.com@s3.amazonaws.com",
            {},
        ),
        ("aws s3 ls --endpoint-url '${{ secrets.ENDPOINT }}'", {}),
        ("aws s3 ls --endpoint-url $ENDPOINT", {}),
        ("aws s3 ls --endpoint-url", {"AWS_ENDPOINT_URL": R2_ENDPOINT}),
        ("aws s3 ls --endpoint-url=", {"AWS_ENDPOINT_URL": R2_ENDPOINT}),
        (f"aws s3 ls --endpoint-url {R2_ENDPOINT}\naws sts get-caller-identity", {}),
        (f"aws s3 ls --endpoint-url {R2_ENDPOINT}; aws s3 ls", {}),
        (f"aws iam list-roles --endpoint-url {R2_ENDPOINT}", {}),
        (f"echo 'aws s3 ls --endpoint-url {R2_ENDPOINT}'", {}),
        (f"aws s3 ls --endpoint-url {R2_ENDPOINT} | bash", {}),
        (
            f"aws s3 ls --endpoint-url {R2_ENDPOINT} > $(aws sts get-caller-identity)",
            {},
        ),
        (f"aws s3 ls --endpoint-url {R2_ENDPOINT} # comment\naws s3 ls", {}),
        ("python upload.py", {"AWS_ENDPOINT_URL": R2_ENDPOINT}),
        ("aws s3 ls --endpoint-url 'unterminated", {}),
        (
            "aws s3 ls",
            {
                "AWS_ENDPOINT_URL": R2_ENDPOINT,
                "AWS_ENDPOINT_URL_S3": "${{ secrets.UNKNOWN_ENDPOINT }}",
            },
        ),
        (
            "aws s3 ls",
            {
                "AWS_ENDPOINT_URL_S3": R2_ENDPOINT,
                "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true",
            },
        ),
    ],
)
def test_aws_or_uncertain_commands_are_not_excluded(run: str, env: dict) -> None:
    assert not uses_only_non_aws_s3(run, env)


@pytest.mark.parametrize("scope", ["step", "job", "workflow"])
def test_r2_keys_are_not_aws_sources_at_any_env_scope(scope: str) -> None:
    workflow = _workflow()
    job = workflow["jobs"]["release"]
    if scope != "step":
        env = job["steps"][0].pop("env")
        (job if scope == "job" else workflow)["env"] = env
    assert extract_aws_credential_sources(workflow, "release.yml") == []


@pytest.mark.parametrize("inherited", [False, True])
def test_r2_step_does_not_hide_aws_in_same_job(inherited: bool) -> None:
    workflow = _workflow()
    job = workflow["jobs"]["release"]
    aws_step = {
        "name": "AWS upload",
        "run": "aws s3 sync dist s3://aws-bucket",
        "env": dict(KEY_ENV),
    }
    job["steps"].append(aws_step)
    if inherited:
        job["env"] = dict(KEY_ENV)
        for step in job["steps"]:
            step.pop("env")
    sources = extract_aws_credential_sources(workflow, "release.yml")
    assert len(sources) == 1
    assert sources[0].uses_access_keys
    assert sources[0].step_name != "Upload"


def test_r2_step_does_not_hide_aws_in_another_job() -> None:
    workflow = _workflow()
    workflow["jobs"]["aws"] = deepcopy(
        _workflow("aws s3 sync dist s3://aws-bucket")["jobs"]["release"]
    )
    sources = extract_aws_credential_sources(workflow, "release.yml")
    assert len(sources) == 1
    assert sources[0].job_name == "aws"


def test_oidc_assumption_is_preserved_alongside_r2() -> None:
    workflow = _workflow()
    job = workflow["jobs"]["release"]
    job["permissions"] = {"id-token": "write"}
    job["steps"].insert(
        0,
        {
            "uses": "aws-actions/configure-aws-credentials@v4",
            "with": {"role-to-assume": "arn:aws:iam::123456789012:role/deploy"},
        },
    )
    sources = extract_aws_credential_sources(workflow, "release.yml")
    assert len(sources) == 1
    assert sources[0].uses_oidc
    assert not sources[0].uses_access_keys


def test_cli_aws_endpoint_overrides_r2_environment() -> None:
    workflow = _workflow("aws s3 ls --endpoint-url https://s3.amazonaws.com")
    step = workflow["jobs"]["release"]["steps"][0]
    step["env"]["AWS_ENDPOINT_URL_S3"] = R2_ENDPOINT
    sources = extract_aws_credential_sources(workflow, "release.yml")
    assert len(sources) == 1
    assert sources[0].uses_access_keys


@pytest.mark.parametrize("caller_env", [False, True])
def test_r2_in_local_composite_is_not_an_aws_source(
    tmp_path: Path, caller_env: bool
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    action_dir = tmp_path / ".github" / "actions" / "upload"
    action_dir.mkdir(parents=True)
    nested_step = {"shell": "bash", "run": R2_RUN}
    caller = {"name": "Upload", "uses": "./.github/actions/upload"}
    (caller if caller_env else nested_step)["env"] = dict(KEY_ENV)
    (action_dir / "action.yml").write_text(
        yaml.safe_dump(
            {
                "runs": {"using": "composite", "steps": [nested_step]},
            }
        )
    )
    workflow = _workflow()
    workflow["jobs"]["release"]["steps"] = [caller]
    (workflow_dir / "release.yml").write_text(yaml.safe_dump(workflow))
    sources, _, _, errors = scan_workflows(str(tmp_path))
    assert not errors
    assert sources == []


def test_mixed_job_reports_aws_static_keys_end_to_end(tmp_path: Path) -> None:
    workflow = _workflow()
    workflow["jobs"]["release"]["steps"].append(
        {
            "name": "AWS upload",
            "env": dict(KEY_ENV),
            "run": "aws s3 sync dist s3://aws-bucket",
        }
    )
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "release.yml").write_text(yaml.safe_dump(workflow))
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--offline",
            "--output-format",
            "sarif",
            "--fail-on",
            "medium",
            "--no-color",
        ],
    )
    assert result.exit_code == 1, result.output
    sarif = json.loads(result.stdout)
    credential_alerts = [
        finding
        for finding in sarif["runs"][0]["results"]
        if finding["ruleId"] == "AS005"
    ]
    assert len(credential_alerts) == 1


def test_r2_exclusion_preserves_other_security_findings(tmp_path: Path) -> None:
    workflow = _workflow()
    workflow["on"] = "issues"
    workflow["jobs"]["release"]["steps"].append(
        {
            "name": "Unsafe title",
            "run": 'echo "${{ github.event.issue.title }}"',
        }
    )
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "release.yml").write_text(yaml.safe_dump(workflow))
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--offline",
            "--output-format",
            "json",
            "--fail-on",
            "medium",
            "--no-color",
        ],
    )
    assert result.exit_code == 1, result.output
    data = json.loads(result.stdout)
    assert data["summary"]["credential_sources"] == 0
    assert len(data["script_injection_findings"]) == 1


def test_r2_only_cli_scan_has_no_aws_findings_or_gate_failure() -> None:
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(FIXTURE),
            "--offline",
            "--output-format",
            "json",
            "--fail-on",
            "medium",
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["workflow_count"] == 1
    assert data["summary"]["credential_sources"] == 0
    assert data["environment_findings"] == []
    assert data["exposure_paths"] == []
    assert data["coverage_gaps"] == []
    assert data["overall_risk"] == "info"


def test_r2_only_sarif_has_no_aws_credential_or_environment_alerts() -> None:
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(FIXTURE),
            "--offline",
            "--output-format",
            "sarif",
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.output
    sarif = json.loads(result.stdout)
    assert sarif["runs"][0]["results"] == []


@pytest.mark.parametrize("output_format", ["terminal", "markdown"])
def test_r2_only_human_reports_do_not_recommend_aws_oidc(output_format: str) -> None:
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(FIXTURE),
            "--offline",
            "--output-format",
            output_format,
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Static AWS credentials" not in result.stdout
    assert "AWS deploy job" not in result.stdout
    assert "Use OIDC role assumption" not in result.stdout
