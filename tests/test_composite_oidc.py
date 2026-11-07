"""OIDC token calibration follows local composites without executing them."""

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from actionscope.analyzers.github_token import analyze_workflow_permissions
from actionscope.cli import main
from actionscope.models import RiskLevel

WORKFLOW = ".github/workflows/docs.yml"
SHA = "a" * 40
AWS_STEP = {
    "uses": f"aws-actions/configure-aws-credentials@{SHA}",
    "with": {"role-to-assume": "${{ secrets.DOCS_ROLE }}"},
}


def write_action(root: Path, name: str, steps: list, **metadata) -> Path:
    path = root / name / "action.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            {
                **metadata,
                "runs": {"using": "composite", "steps": steps},
            }
        )
    )
    return path


def workflow(steps: list) -> dict:
    return {
        "on": "push",
        "jobs": {
            "docs": {
                "runs-on": "ubuntu-latest",
                "permissions": {"id-token": "write", "contents": "read"},
                "steps": steps,
            }
        },
    }


def token_risk(data: dict, root: Path | None) -> RiskLevel:
    permissions = analyze_workflow_permissions(
        data,
        WORKFLOW,
        str(root) if root else None,
    )
    return next(p.risk_level for p in permissions if p.scope == "id-token")


def test_direct_and_composite_aws_consumers_have_same_classification(tmp_path):
    write_action(tmp_path, ".github/composites/docs", [AWS_STEP])
    assert token_risk(workflow([AWS_STEP]), tmp_path) is RiskLevel.INFO
    assert (
        token_risk(
            workflow(
                [
                    {"uses": "./.github/composites/docs"},
                ]
            ),
            tmp_path,
        )
        is RiskLevel.INFO
    )


def test_nested_composites_resolve_defaults_and_caller_inputs(tmp_path):
    write_action(
        tmp_path,
        "inner",
        [
            {
                **AWS_STEP,
                "with": {"role-to-assume": "${{ inputs.role }}"},
            }
        ],
        inputs={"role": {"default": ""}},
    )
    write_action(
        tmp_path,
        "outer",
        [
            {
                "uses": "./inner",
                "with": {"role": "${{ inputs.role }}"},
            }
        ],
        inputs={"role": {"default": "${{ secrets.DOCS_ROLE }}"}},
    )
    assert token_risk(workflow([{"uses": "./outer"}]), tmp_path) is RiskLevel.INFO
    assert (
        token_risk(
            workflow(
                [
                    {
                        "uses": "./inner",
                        "with": {"role": "${{ secrets.OTHER_ROLE }}"},
                    }
                ]
            ),
            tmp_path,
        )
        is RiskLevel.INFO
    )
    assert token_risk(workflow([{"uses": "./inner"}]), tmp_path) is RiskLevel.HIGH


@pytest.mark.parametrize("inputs", [{"role": {}}, {"role": None}, {}])
def test_omitted_input_does_not_establish_oidc_consumer(tmp_path, inputs):
    write_action(
        tmp_path,
        "auth",
        [
            {
                **AWS_STEP,
                "with": {"role-to-assume": "${{ inputs.role }}"},
            }
        ],
        inputs=inputs,
    )
    data = workflow([{"uses": "./auth"}])
    assert token_risk(data, tmp_path) is RiskLevel.HIGH
    target = tmp_path / WORKFLOW
    target.parent.mkdir(parents=True)
    target.write_text(yaml.safe_dump(data))
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--offline",
            "--fail-on",
            "high",
            "--output-format",
            "json",
        ],
    )
    assert result.exit_code == 1, result.output
    assert any(
        p["scope"] == "id-token" and p["risk_level"] == "high"
        for p in json.loads(result.stdout)["github_token_permissions"]
    )


def test_explicit_runtime_input_is_preserved(tmp_path):
    write_action(
        tmp_path,
        "auth",
        [
            {
                **AWS_STEP,
                "with": {"role-to-assume": "${{ inputs.role }}"},
            }
        ],
        inputs={"role": {}},
    )
    data = workflow(
        [
            {
                "uses": "./auth",
                "with": {"role": "${{ inputs.deploy_role }}"},
            }
        ]
    )
    assert token_risk(data, tmp_path) is RiskLevel.INFO


def test_no_root_does_not_inspect_local_files(tmp_path):
    write_action(tmp_path, "auth", [AWS_STEP])
    assert token_risk(workflow([{"uses": "./auth"}]), None) is RiskLevel.HIGH


def test_composite_in_other_job_does_not_downgrade_explicit_grant(tmp_path):
    write_action(tmp_path, "auth", [AWS_STEP])
    data = workflow([{"run": "pytest"}])
    data["jobs"]["publish"] = {"steps": [{"uses": "./auth"}]}
    assert token_risk(data, tmp_path) is RiskLevel.HIGH


def test_inherited_grant_requires_consumer_in_every_inheriting_job(tmp_path):
    write_action(tmp_path, "auth", [AWS_STEP])
    data = workflow([{"uses": "./auth"}])
    data["permissions"] = data["jobs"]["docs"].pop("permissions")
    assert token_risk(data, tmp_path) is RiskLevel.INFO
    data["jobs"]["test"] = {"steps": [{"run": "pytest"}]}
    assert token_risk(data, tmp_path) is RiskLevel.HIGH
    data["jobs"]["test"]["permissions"] = {"contents": "read"}
    assert token_risk(data, tmp_path) is RiskLevel.INFO


@pytest.mark.parametrize(
    "metadata",
    [
        "[broken",
        "[]",
        "runs: {using: node24, main: index.js}",
        "runs: {using: composite, steps: invalid}",
        "#" + "x" * 262145,
    ],
)
def test_uninspectable_action_keeps_warning(tmp_path, metadata):
    path = write_action(tmp_path, "auth", [AWS_STEP])
    path.write_text(metadata)
    assert token_risk(workflow([{"uses": "./auth"}]), tmp_path) is RiskLevel.HIGH


def test_missing_action_keeps_warning(tmp_path):
    assert token_risk(workflow([{"uses": "./missing"}]), tmp_path) is RiskLevel.HIGH


def test_invalid_yaml_timestamp_in_nested_action_does_not_crash_scan(tmp_path):
    path = write_action(tmp_path, "inner", [AWS_STEP])
    path.write_text(path.read_text() + "date: 2024-13-45\n")
    write_action(tmp_path, "outer", [{"uses": "./inner"}])
    data = workflow([{"uses": "./outer"}])
    assert token_risk(data, tmp_path) is RiskLevel.HIGH
    target = tmp_path / WORKFLOW
    target.parent.mkdir(parents=True)
    target.write_text(yaml.safe_dump(data))
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--offline",
            "--output-format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert any(
        p["scope"] == "id-token" and p["risk_level"] == "high"
        for p in json.loads(result.stdout)["github_token_permissions"]
    )


@pytest.mark.parametrize("malformed_file", ["workflow", "composite"])
def test_invalid_yaml_timestamp_at_scan_entrypoints_is_reported(
    tmp_path, malformed_file
):
    path = write_action(tmp_path, "auth", [AWS_STEP])
    target = tmp_path / WORKFLOW
    target.parent.mkdir(parents=True)
    target.write_text(yaml.safe_dump(workflow([{"uses": "./auth"}])))
    malformed = target if malformed_file == "workflow" else path
    malformed.write_text(malformed.read_text() + "date: 2024-13-45\n")
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--offline",
            "--output-format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["errors"]
    assert data["coverage_status"] == "partial"


def test_cycle_is_bounded_and_keeps_warning(tmp_path):
    write_action(tmp_path, "one", [{"uses": "./two"}])
    write_action(tmp_path, "two", [{"uses": "./one"}])
    assert token_risk(workflow([{"uses": "./one"}]), tmp_path) is RiskLevel.HIGH


def test_symlink_loop_keeps_warning(tmp_path):
    (tmp_path / "auth").symlink_to(tmp_path / "auth", target_is_directory=True)
    assert token_risk(workflow([{"uses": "./auth"}]), tmp_path) is RiskLevel.HIGH


def test_invalid_utf8_keeps_warning(tmp_path):
    path = write_action(tmp_path, "auth", [AWS_STEP])
    path.write_bytes(b"\xff")
    assert token_risk(workflow([{"uses": "./auth"}]), tmp_path) is RiskLevel.HIGH


def test_recursion_depth_is_bounded(tmp_path):
    for index in range(9):
        steps = [AWS_STEP] if index == 8 else [{"uses": f"./a{index + 1}"}]
        write_action(tmp_path, f"a{index}", steps)
    assert token_risk(workflow([{"uses": "./a0"}]), tmp_path) is RiskLevel.HIGH


def test_file_visit_budget_is_bounded(tmp_path):
    calls = []
    for index in range(65):
        write_action(tmp_path, f"a{index}", [AWS_STEP] if index == 64 else [])
        calls.append({"uses": f"./a{index}"})
    assert token_risk(workflow(calls), tmp_path) is RiskLevel.HIGH


def test_path_and_symlink_escape_keep_warning(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    external = write_action(tmp_path, "outside", [AWS_STEP])
    (root / "link").symlink_to(external.parent, target_is_directory=True)
    (root / "auth").mkdir()
    (root / "auth" / "action.yml").symlink_to(external)
    for uses in ("./../outside", "./link", "./auth"):
        assert token_risk(workflow([{"uses": uses}]), root) is RiskLevel.HIGH


@pytest.mark.parametrize(
    "command",
    [
        "cosign sign --yes example.com/image@sha256:abc",
        "cosign sign-blob --yes dist/file.tar.gz",
        "cosign sign \\\n      --yes example.com/image@sha256:abc",
        'for tag in "$TAGS"\ndo\n  cosign sign image@sha256:abc\ndone',
    ],
)
def test_keyless_cosign_is_recognized_directly_and_in_composite(tmp_path, command):
    step = {"run": command, "shell": "bash"}
    write_action(tmp_path, "sign", [step])
    assert token_risk(workflow([step]), tmp_path) is RiskLevel.INFO
    assert token_risk(workflow([{"uses": "./sign"}]), tmp_path) is RiskLevel.INFO


@pytest.mark.parametrize(
    "command",
    [
        "cosign sign --key cosign.key image",
        "cosign sign --key=env://COSIGN_PRIVATE_KEY image",
        "cosign sign --sk image",
        "cosign sign --oidc-disable-ambient-providers image",
        "cosign sign --signing-config config.json image",
        "cosign sign --identity-token token image",
        "cosign sign --oidc-provider custom image",
        'echo "cosign sign --yes image"',
        "# cosign sign --yes image",
        "cat <<'EOF'\ncosign sign --yes image\nEOF",
    ],
)
def test_non_keyless_or_non_executed_cosign_keeps_warning(tmp_path, command):
    write_action(tmp_path, "sign", [{"run": command, "shell": "bash"}])
    assert token_risk(workflow([{"uses": "./sign"}]), tmp_path) is RiskLevel.HIGH


@pytest.mark.parametrize("layer", ["workflow", "job", "caller", "child"])
def test_explicit_identity_token_environment_keeps_warning(tmp_path, layer):
    env = {"SIGSTORE_ID_TOKEN": "${{ secrets.EXTERNAL_TOKEN }}"}
    child = {"run": "cosign sign --yes image", "shell": "bash"}
    caller = {"uses": "./sign"}
    data = workflow([caller])
    if layer == "workflow":
        data["env"] = env
    elif layer == "job":
        data["jobs"]["docs"]["env"] = env
    elif layer == "caller":
        caller["env"] = env
    else:
        child["env"] = env
    write_action(tmp_path, "sign", [child])
    assert token_risk(data, tmp_path) is RiskLevel.HIGH


def test_docker_password_login_is_not_an_oidc_consumer(tmp_path):
    login = {
        "uses": f"docker/login-action@{SHA}",
        "with": {
            "username": "${{ github.actor }}",
            "password": "${{ secrets.GITHUB_TOKEN }}",
        },
    }
    write_action(tmp_path, "login", [login])
    assert token_risk(workflow([login]), tmp_path) is RiskLevel.HIGH
    assert token_risk(workflow([{"uses": "./login"}]), tmp_path) is RiskLevel.HIGH


def test_yaml_action_filename_and_workflow_file_scan_root(tmp_path):
    path = write_action(tmp_path, "auth", [AWS_STEP])
    path.rename(path.with_suffix(".yaml"))
    target = tmp_path / WORKFLOW
    target.parent.mkdir(parents=True)
    target.write_text("on: push")
    assert token_risk(workflow([{"uses": "./auth"}]), target) is RiskLevel.INFO


def test_offline_docs_wrapper_scan_gate_and_unknown_iam_coverage(tmp_path):
    write_action(tmp_path, ".github/composites/docs", [AWS_STEP])
    target = tmp_path / WORKFLOW
    target.parent.mkdir(parents=True)
    target.write_text(
        yaml.safe_dump(
            workflow(
                [
                    {"uses": "./.github/composites/docs"},
                ]
            )
        )
    )
    runner = CliRunner()
    args = ["scan", str(tmp_path), "--offline", "--fail-on", "high"]
    result = runner.invoke(main, [*args, "--output-format", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    id_token = next(
        p for p in data["github_token_permissions"] if p["scope"] == "id-token"
    )
    assert id_token["risk_level"] == "info"
    binding = data["findings"][0]
    assert binding["role_reference_kind"] == "secret"
    assert binding["policy_source"] == "dynamic_reference"
    assert binding["policy_coverage_complete"] is False
    assert data["coverage_status"] == "partial"
    assert data["coverage_gaps"]
    result = runner.invoke(main, [*args, "--output-format", "sarif"])
    assert result.exit_code == 0, result.output
    results = json.loads(result.stdout)["runs"][0]["results"]
    assert not any(r["ruleId"] == "AS004" for r in results)


def test_unused_grant_still_fails_high_gate(tmp_path):
    target = tmp_path / WORKFLOW
    target.parent.mkdir(parents=True)
    target.write_text(yaml.safe_dump(workflow([{"uses": "./missing"}])))
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--offline",
            "--fail-on",
            "high",
            "--output-format",
            "json",
        ],
    )
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout)["overall_risk"] == "high"
