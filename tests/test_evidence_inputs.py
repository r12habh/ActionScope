"""Ground-truth fixtures for explicit evidence, not live AWS validation."""

from __future__ import annotations

import copy
import json
from urllib.parse import quote

import pytest
import yaml
from click.testing import CliRunner

from actionscope.cli import main
from actionscope.evidence import EvidenceError, load_iam_snapshot, read_evidence_json
from actionscope.parsers.policy_json import extract_actions_from_policy

ARN = "arn:aws:iam::111111111111:role/ci-deploy"
MANAGED = "arn:aws:iam::111111111111:policy/deploy"
SHA = "a" * 40
ALLOW = {"Effect": "Allow", "Action": "s3:DeleteBucket", "Resource": "*"}


def document(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def trust(subject="repo:example/app:environment:production"):
    return document(
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {
                "Federated": (
                    "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
                )
            },
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": subject,
                }
            },
        }
    )


def snapshot():
    return {
        "RoleDetailList": [
            {
                "Arn": ARN,
                "RoleName": "ci-deploy",
                "AssumeRolePolicyDocument": trust(),
                "RolePolicyList": [
                    {"PolicyName": "inline", "PolicyDocument": document(ALLOW)}
                ],
                "AttachedManagedPolicies": [],
            }
        ],
        "Policies": [],
        "IsTruncated": False,
    }


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return path


def write_workflow(root, role=ARN, *, environment=None, on="push", env=None):
    steps = (
        []
        if role is None
        else [
            {
                "name": "AWS",
                "uses": f"aws-actions/configure-aws-credentials@{SHA}",
                "with": {"role-to-assume": role},
            }
        ]
    )
    job = {
        "runs-on": "ubuntu-latest",
        "permissions": {"id-token": "write"},
        "steps": steps,
    }
    if environment is not None:
        job["environment"] = environment
    data = {"on": on, "jobs": {"deploy": job}}
    if env:
        data["env"] = env
    path = root / ".github/workflows/deploy.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data))
    return data


def scan(root, *flags, fmt="json"):
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(root),
            "--offline",
            "--output-format",
            fmt,
            *map(str, flags),
        ],
    )
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout) if fmt in {"json", "sarif"} else result.stdout


def test_literal_snapshot_match_is_offline_and_not_live_verification(
    tmp_path, monkeypatch
):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("offline scan attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    app = tmp_path / "app"
    write_workflow(app)
    export = write_json(tmp_path / "private/iam.json", snapshot())
    data = scan(app, "--iam-snapshot", export)
    binding = data["findings"][0]
    assert binding["policy_source"] == "aws_snapshot"
    assert binding["authorization_evaluated"] is False
    assert data["coverage_status"] == "partial"
    assert binding["policy_evidence"]["policy_statements"] == [ALLOW]
    assert len(binding["policy_evidence"]["evidence_sources"][0]["sha256"]) == 64


def test_managed_policy_default_version_only(tmp_path):
    data = snapshot()
    data["RoleDetailList"][0]["AttachedManagedPolicies"] = [{"PolicyArn": MANAGED}]
    data["Policies"] = [
        {
            "Arn": MANAGED,
            "PolicyVersionList": [
                {
                    "IsDefaultVersion": False,
                    "Document": document({**ALLOW, "Action": "iam:*"}),
                },
                {
                    "IsDefaultVersion": True,
                    "Document": quote(
                        json.dumps(document({**ALLOW, "Action": "s3:GetObject"}))
                    ),
                },
            ],
        }
    ]
    finding = load_iam_snapshot(str(write_json(tmp_path / "iam.json", data)))[0]
    assert {a.action for a in finding.actions} == {"s3:DeleteBucket", "s3:GetObject"}


def test_missing_attachment_and_boundary_remain_unknown(tmp_path):
    data = snapshot()
    role = data["RoleDetailList"][0]
    role["AttachedManagedPolicies"] = [{"PolicyArn": MANAGED}]
    role["PermissionsBoundary"] = {"PermissionsBoundaryArn": MANAGED}
    finding = load_iam_snapshot(str(write_json(tmp_path / "iam.json", data)))[0]
    assert finding.metadata["unresolved_policy_attachments"] == [MANAGED]
    assert finding.metadata["permissions_boundaries"] == [
        {"arn": MANAGED, "document": None}
    ]
    assert finding.metadata["policy_coverage_complete"] is False


def test_snapshot_identity_does_not_fall_back_to_same_role_name(tmp_path):
    app = tmp_path / "app"
    write_workflow(app, ARN.replace("111111111111", "222222222222"))
    data = scan(app, "--iam-snapshot", write_json(tmp_path / "iam.json", snapshot()))
    assert data["summary"]["policies_found"] == 0


def test_duplicate_and_truncated_exports_rejected(tmp_path):
    data = snapshot()
    data["IsTruncated"] = True
    path = write_json(tmp_path / "iam.json", data)
    with pytest.raises(EvidenceError, match="truncated"):
        load_iam_snapshot(str(path))
    data["IsTruncated"] = False
    data["RoleDetailList"].append(copy.deepcopy(data["RoleDetailList"][0]))
    write_json(path, data)
    with pytest.raises(EvidenceError, match="duplicate"):
        load_iam_snapshot(str(path))


@pytest.mark.parametrize(
    "value",
    [
        [],
        {},
        {"RoleDetailList": "invalid"},
        {"RoleDetailList": [None]},
        {"RoleDetailList": [{"Arn": "${{ secrets.ROLE }}"}]},
    ],
)
def test_malformed_snapshot_rejected(tmp_path, value):
    with pytest.raises(EvidenceError):
        load_iam_snapshot(str(write_json(tmp_path / "iam.json", value)))


def test_input_size_and_duplicate_key_guards(tmp_path):
    path = tmp_path / "input.json"
    path.write_text('{"x":1,"x":2}')
    with pytest.raises(EvidenceError, match="Duplicate"):
        read_evidence_json(str(path))
    with pytest.raises(EvidenceError, match="exceeds"):
        read_evidence_json(str(path), limit=2)


def test_invalid_policy_document_is_not_an_empty_safe_policy(tmp_path):
    data = snapshot()
    data["RoleDetailList"][0]["RolePolicyList"][0]["PolicyDocument"] = document(None)
    with pytest.raises(EvidenceError):
        load_iam_snapshot(str(write_json(tmp_path / "iam.json", data)))


def mapping(role=ARN, **extra):
    return {
        "version": 1,
        "roles": [
            {
                "workflow": ".github/workflows/deploy.yml",
                "job": "deploy",
                "role_arn": role,
                **extra,
            }
        ],
    }


def test_owner_mapping_resolves_secret_without_claiming_secret_access(tmp_path):
    app = tmp_path / "app"
    write_workflow(app, "${{ secrets.ROLE }}")
    export = write_json(tmp_path / "private/iam.json", snapshot())
    role_map = write_json(tmp_path / "private/map.json", mapping())
    data = scan(app, "--iam-snapshot", export, "--role-map", role_map)
    binding = data["findings"][0]
    assert binding["role_arn"] == ARN
    assert binding["original_role_reference"] == "${{ secrets.ROLE }}"
    assert binding["role_reference_kind"] == "secret"
    assert binding["role_resolution"] == "owner_mapping"
    assert binding["match_confidence"] == "medium"
    assert binding["role_resolution_evidence"]["sha256"]


@pytest.mark.parametrize(
    "entry",
    [
        mapping(workflow="../escape.yml"),
        mapping(workflow="/tmp/deploy.yml"),
        mapping(job="other"),
        mapping(role="invalid"),
        mapping(unknown=True),
        {"version": 1, "roles": mapping()["roles"] * 2},
    ],
)
def test_invalid_or_overlapping_role_map_fails_closed(tmp_path, entry):
    app = tmp_path / "app"
    write_workflow(app, "${{ secrets.ROLE }}")
    role_map = write_json(tmp_path / "map.json", entry)
    result = CliRunner().invoke(
        main, ["scan", str(app), "--offline", "--role-map", str(role_map)]
    )
    assert result.exit_code == 2


def test_mapping_cannot_override_literal_role(tmp_path):
    app = tmp_path / "app"
    write_workflow(app)
    role_map = write_json(
        tmp_path / "map.json", mapping(role=ARN.replace("111", "222"))
    )
    result = CliRunner().invoke(
        main, ["scan", str(app), "--offline", "--role-map", str(role_map)]
    )
    assert result.exit_code == 2


def test_multi_step_mapping_requires_step_selector(tmp_path):
    app = tmp_path / "app"
    data = write_workflow(app, "${{ secrets.ROLE }}")
    second = copy.deepcopy(data["jobs"]["deploy"]["steps"][0])
    second["name"] = "Other AWS"
    data["jobs"]["deploy"]["steps"].append(second)
    path = app / ".github/workflows/deploy.yml"
    path.write_text(yaml.safe_dump(data))
    role_map = write_json(tmp_path / "map.json", mapping())
    result = CliRunner().invoke(
        main, ["scan", str(app), "--offline", "--role-map", str(role_map)]
    )
    assert result.exit_code == 2
    write_json(role_map, mapping(step="AWS"))
    data = scan(app, "--role-map", role_map)
    assert [f["role_resolution"] for f in data["findings"]] == [
        "owner_mapping",
        "workflow",
    ]


@pytest.mark.parametrize("value", [ARN, "${{ secrets.UNKNOWN }}", "${{ env.ROLE }}"])
def test_literal_env_resolution_is_bounded_and_conservative(tmp_path, value):
    app = tmp_path / "app"
    write_workflow(app, "${{ env.ROLE }}", env={"ROLE": value})
    data = scan(app, "--iam-snapshot", write_json(tmp_path / "iam.json", snapshot()))
    found = data["findings"][0]
    assert found["role_resolution"] == ("literal_env" if value == ARN else "workflow")
    assert data["summary"]["policies_found"] == (1 if value == ARN else 0)


def test_separate_iam_root_matches_and_deduplicates(tmp_path):
    app = tmp_path / "app"
    write_workflow(app)
    infra = tmp_path / "infra"
    write_json(infra / "iam/ci-deploy.json", document(ALLOW))
    assert scan(app)["summary"]["policies_found"] == 0
    data = scan(app, "--iam-path", infra, "--iam-path", infra)
    assert data["summary"]["policies_found"] == 1
    evidence = data["findings"][0]["policy_evidence"]["evidence_sources"]
    assert len(evidence) == 1
    assert evidence[0]["file"] == "iam/ci-deploy.json"
    assert evidence[0]["sha256"]
    assert data["findings"][0]["match_confidence"] == "medium"
    assert data["coverage_status"] == "partial"


def test_iam_root_rejects_symlinks(tmp_path):
    app = tmp_path / "app"
    write_workflow(app)
    infra = tmp_path / "infra"
    infra.mkdir()
    (infra / "escape.json").symlink_to(tmp_path / "other.json")
    result = CliRunner().invoke(main, ["scan", str(app), "--iam-path", str(infra)])
    assert result.exit_code == 2


def test_snapshot_has_precedence_over_repository_policy(tmp_path):
    app = tmp_path / "app"
    write_workflow(app)
    write_json(app / "iam/ci-deploy.json", document({**ALLOW, "Action": "iam:*"}))
    data = scan(app, "--iam-snapshot", write_json(tmp_path / "iam.json", snapshot()))
    assert {a["action"] for a in data["findings"][0]["actions"]} == {"s3:DeleteBucket"}


def test_cloud_first_candidates_do_not_resolve_configured_secret(tmp_path):
    app = tmp_path / "app"
    write_workflow(app, "${{ secrets.ROLE }}", environment="production")
    export = write_json(tmp_path / "iam.json", snapshot())
    data = scan(app, "--iam-snapshot", export, "--github-repo", "example/app")
    assert len(data["findings"]) == 2
    configured, candidate = data["findings"]
    assert configured["role_arn"] == "${{ secrets.ROLE }}"
    assert configured["policy_source"] == "dynamic_reference"
    assert candidate["role_resolution"] == "trust_candidate"
    assert candidate["match_confidence"] == "medium"
    assert data["summary"]["trust_candidates"] == 1
    assert any(
        g["gap_type"] == "potential_oidc_identity" for g in data["coverage_gaps"]
    )
    assert data["exposure_paths"] == []


def test_job_token_can_reach_candidate_without_an_aws_action(tmp_path):
    app = tmp_path / "app"
    write_workflow(app, None, environment="production")
    data = scan(
        app,
        "--iam-snapshot",
        write_json(tmp_path / "iam.json", snapshot()),
        "--github-repo",
        "example/app",
    )
    assert data["findings"][0]["role_resolution"] == "trust_candidate"


@pytest.mark.parametrize(
    "change",
    [
        "wildcard",
        "extra_claim",
        "deny",
        "wrong_repo",
        "no_token",
        "dynamic_env",
        "workflow_call",
    ],
)
def test_unsupported_trust_context_does_not_create_candidate(tmp_path, change):
    app = tmp_path / "app"
    workflow = write_workflow(app, None, environment="production")
    data = snapshot()
    statement = data["RoleDetailList"][0]["AssumeRolePolicyDocument"]["Statement"][0]
    if change == "wildcard":
        statement["Condition"]["StringEquals"][
            "token.actions.githubusercontent.com:sub"
        ] = "repo:example/*"
    elif change == "extra_claim":
        statement["Condition"]["StringEquals"][
            "token.actions.githubusercontent.com:repository_id"
        ] = "123"
    elif change == "deny":
        data["RoleDetailList"][0]["AssumeRolePolicyDocument"]["Statement"].append(
            {**statement, "Effect": "Deny"}
        )
    elif change == "wrong_repo":
        statement["Condition"]["StringEquals"][
            "token.actions.githubusercontent.com:sub"
        ] = "repo:other/app:environment:production"
    elif change == "no_token":
        workflow["jobs"]["deploy"]["permissions"] = {"contents": "read"}
    elif change == "dynamic_env":
        workflow["jobs"]["deploy"]["environment"] = "${{ inputs.env }}"
    else:
        workflow["on"] = "workflow_call"
    (app / ".github/workflows/deploy.yml").write_text(yaml.safe_dump(workflow))
    result = scan(
        app,
        "--iam-snapshot",
        write_json(tmp_path / "iam.json", data),
        "--github-repo",
        "example/app",
    )
    assert result["summary"]["trust_candidates"] == 0


def test_branch_scoped_candidate_requires_single_literal_branch(tmp_path):
    app = tmp_path / "app"
    write_workflow(app, None, on={"push": {"branches": ["main"]}})
    data = snapshot()
    data["RoleDetailList"][0]["AssumeRolePolicyDocument"] = trust(
        "repo:example/app:ref:refs/heads/main"
    )
    result = scan(
        app,
        "--iam-snapshot",
        write_json(tmp_path / "iam.json", data),
        "--github-repo",
        "example/app",
    )
    assert result["summary"]["trust_candidates"] == 1


def test_deny_and_condition_preserved_and_marked_partial(tmp_path):
    deny = {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}
    conditional = {
        **ALLOW,
        "Condition": {"StringEquals": {"aws:PrincipalTag/team": "deploy"}},
    }
    finding = extract_actions_from_policy(document(conditional, deny), "fixture.json")
    assert finding.metadata["policy_statements"] == [conditional, deny]
    assert finding.metadata["policy_coverage_complete"] is False
    assert finding.metadata["authorization_evaluated"] is False
    assert len(finding.metadata["uninspectable_policy_elements"]) == 2


@pytest.mark.parametrize("fmt", ["terminal", "markdown", "sarif"])
def test_reports_and_saved_reports_retain_limits(tmp_path, fmt):
    app = tmp_path / "app"
    write_workflow(app, None, environment="production")
    export = write_json(tmp_path / "iam.json", snapshot())
    flags = ["--iam-snapshot", export, "--github-repo", "example/app"]
    result = scan(app, *flags, fmt=fmt)
    serialized = json.dumps(result) if isinstance(result, dict) else result
    assert "not evaluated" in serialized
    assert (
        "trust_candidate" in serialized or "Potential trust reachability" in serialized
    )
    saved = write_json(tmp_path / "saved.json", scan(app, *flags))
    result = CliRunner().invoke(main, ["report", str(saved), "--format", fmt])
    assert result.exit_code == 0, result.output
    assert "not evaluated" in result.stdout


def test_state_does_not_store_iam_export_or_mapping_contents(tmp_path):
    app = tmp_path / "app"
    write_workflow(app, "${{ secrets.ROLE }}")
    export = write_json(tmp_path / "private/iam.json", snapshot())
    role_map = write_json(tmp_path / "private/map.json", mapping())
    state = tmp_path / "state.json"
    scan(
        app,
        "--iam-snapshot",
        export,
        "--role-map",
        role_map,
        "--save-state",
        "--state-file",
        state,
    )
    text = state.read_text()
    assert "111111111111" not in text
    assert str(tmp_path) not in text
    assert "DOCS_ROLE" not in text


def test_snapshot_cannot_be_mislabeled_live(tmp_path):
    app = tmp_path / "app"
    write_workflow(app)
    export = write_json(tmp_path / "iam.json", snapshot())
    result = CliRunner().invoke(
        main, ["scan", str(app), "--iam-snapshot", str(export), "--aws-verify"]
    )
    assert result.exit_code == 2


def test_plain_json_policy_keeps_percent_encoded_resource_names(tmp_path):
    data = snapshot()
    policy = document({**ALLOW, "Resource": "arn:aws:s3:::example/a%2Fb"})
    data["RoleDetailList"][0]["RolePolicyList"][0]["PolicyDocument"] = json.dumps(
        policy
    )
    finding = load_iam_snapshot(str(write_json(tmp_path / "iam.json", data)))[0]
    assert finding.actions[0].resource == "arn:aws:s3:::example/a%2Fb"


def test_nested_roots_are_order_independent(tmp_path):
    app, infra = tmp_path / "app", tmp_path / "infra"
    write_workflow(app)
    write_json(infra / "iam/ci-deploy.json", document(ALLOW))
    first = scan(app, "--iam-path", infra / "iam", "--iam-path", infra)
    second = scan(app, "--iam-path", infra, "--iam-path", infra / "iam")
    assert first["findings"] == second["findings"]


def test_ambiguous_same_name_policies_are_not_chosen_by_risk(tmp_path):
    app = tmp_path / "app"
    write_workflow(app)
    one, two = tmp_path / "one", tmp_path / "two"
    write_json(one / "ci-deploy.json", document(ALLOW))
    write_json(two / "ci-deploy.json", document({**ALLOW, "Action": "iam:*"}))
    data = scan(app, "--iam-path", one, "--iam-path", two)
    assert data["summary"]["policies_found"] == 0
    assert "multiple" in data["findings"][0]["match_reason"]


def test_nested_env_expression_is_not_treated_as_literal(tmp_path):
    app = tmp_path / "app"
    write_workflow(app, "${{ env.ROLE }}", env={"ROLE": "${{ env.NEXT }}", "NEXT": ARN})
    data = scan(app, "--iam-snapshot", write_json(tmp_path / "iam.json", snapshot()))
    assert data["findings"][0]["role_resolution"] == "workflow"
    assert data["summary"]["policies_found"] == 0


def test_step_env_shadows_workflow_env(tmp_path):
    app = tmp_path / "app"
    workflow = write_workflow(app, "${{ env.ROLE }}", env={"ROLE": ARN})
    workflow["jobs"]["deploy"]["steps"][0]["env"] = {"ROLE": "${{ secrets.OTHER }}"}
    (app / ".github/workflows/deploy.yml").write_text(yaml.safe_dump(workflow))
    data = scan(app, "--iam-snapshot", write_json(tmp_path / "iam.json", snapshot()))
    assert data["summary"]["policies_found"] == 0


def test_cloudformation_boundary_and_deny_survive_normalization():
    from actionscope.parsers.cloudformation import (
        extract_iam_policies_from_cloudformation,
    )

    data = {
        "Resources": {
            "Deploy": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "ci-deploy",
                    "PermissionsBoundary": MANAGED,
                    "Policies": [
                        {
                            "PolicyName": "inline",
                            "PolicyDocument": document(
                                ALLOW,
                                {**ALLOW, "Effect": "Deny"},
                            ),
                        }
                    ],
                },
            }
        }
    }
    finding = extract_iam_policies_from_cloudformation(data, "fixture.yml")[0]
    assert finding.metadata["permissions_boundaries"] == [{"reference": MANAGED}]
    assert finding.metadata["policy_coverage_complete"] is False
    assert any(s["Effect"] == "Deny" for s in finding.metadata["policy_statements"])


def test_terraform_role_boundary_is_preserved():
    from actionscope.parsers.terraform import extract_iam_policies_from_terraform

    data = {
        "resource": [
            {
                "aws_iam_role": {
                    "deploy": {"name": "ci-deploy", "permissions_boundary": MANAGED}
                }
            },
            {
                "aws_iam_role_policy": {
                    "deploy": {
                        "role": "${aws_iam_role.deploy.name}",
                        "policy": json.dumps(document(ALLOW)),
                    }
                }
            },
        ]
    }
    findings = extract_iam_policies_from_terraform(data, "fixture.tf")
    finding = next(f for f in findings if f.role_name == "ci-deploy")
    assert finding.metadata["permissions_boundaries"] == [{"reference": MANAGED}]
    assert finding.metadata["policy_coverage_complete"] is False


def test_live_verifier_rejects_same_named_role_in_wrong_account(monkeypatch):
    from actionscope.models import AwsCredentialSource
    from actionscope.verifiers import aws_verifier

    monkeypatch.setattr(
        aws_verifier,
        "fetch_role_policies",
        lambda *args: {
            "role_arn": ARN.replace("111111111111", "222222222222"),
            "all_statements": [ALLOW],
        },
    )
    source = AwsCredentialSource("fixture.yml", "deploy", "AWS", ARN, False, True, None)
    finding = aws_verifier.verify_credential_source(source, None)
    assert finding.metadata["aws_verification_status"] == "error"


def test_live_verifier_retains_boundary_without_extra_calls(monkeypatch):
    from actionscope.models import AwsCredentialSource
    from actionscope.verifiers import aws_verifier

    monkeypatch.setattr(
        aws_verifier,
        "fetch_role_policies",
        lambda *args: {
            "role_arn": ARN,
            "all_statements": [ALLOW],
            "permissions_boundary": {"PermissionsBoundaryArn": MANAGED},
        },
    )
    source = AwsCredentialSource("fixture.yml", "deploy", "AWS", ARN, False, True, None)
    finding = aws_verifier.verify_credential_source(source, None)
    assert finding.metadata["policy_coverage_complete"] is False
    assert finding.metadata["permissions_boundaries"] == [
        {"PermissionsBoundaryArn": MANAGED}
    ]


def test_synthetic_reference_analysis_is_reproducible():
    from scripts.evaluate_offline_evidence import evaluate

    result = evaluate()
    assert result["observations"]["owner_mapping"]["policy_matches"] == 1
    assert "synthetic" in result["scope"]


def test_unrelated_snapshot_trust_does_not_raise_workflow_risk(tmp_path):
    app = tmp_path / "app"
    write_workflow(app)
    data = snapshot()
    other = copy.deepcopy(data["RoleDetailList"][0])
    other["Arn"] = ARN.replace("ci-deploy", "unrelated")
    other["RoleName"] = "unrelated"
    del other["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]
    data["RoleDetailList"].append(other)
    result = scan(app, "--iam-snapshot", write_json(tmp_path / "iam.json", data))
    assert not any(
        f["issue_id"] == "missing_sub" for f in result["oidc_trust_findings"]
    )


def test_supplied_repository_identity_requires_snapshot(tmp_path):
    write_workflow(tmp_path)
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--offline", "--github-repo", "example/app"]
    )
    assert result.exit_code == 2


def test_snapshot_arn_matching_respects_partition(tmp_path):
    app = tmp_path / "app"
    write_workflow(app, ARN.replace("arn:aws:", "arn:aws-us-gov:"))
    result = scan(app, "--iam-snapshot", write_json(tmp_path / "iam.json", snapshot()))
    assert result["summary"]["policies_found"] == 0


@pytest.mark.parametrize("number", ["9" * 300, "NaN", "1e99999"])
def test_numeric_json_bombs_and_nonstandard_constants_are_rejected(tmp_path, number):
    path = tmp_path / "input.json"
    path.write_text('{"RoleDetailList":[],"value":' + number + "}")
    with pytest.raises(EvidenceError):
        read_evidence_json(str(path))


def test_oversized_iam_source_rejected_before_parser(tmp_path):
    app = tmp_path / "app"
    write_workflow(app)
    infra = tmp_path / "infra"
    infra.mkdir()
    with (infra / "huge.json").open("wb") as handle:
        handle.truncate(20 * 1024 * 1024 + 1)
    result = CliRunner().invoke(
        main, ["scan", str(app), "--offline", "--iam-path", str(infra)]
    )
    assert result.exit_code == 2
    assert "before parsing" in result.output


def test_zero_iam_alerts_still_preserve_unknown_authorization_in_sarif(tmp_path):
    app = tmp_path / "app"
    write_workflow(app)
    data = snapshot()
    data["RoleDetailList"][0]["RolePolicyList"] = []
    export = write_json(tmp_path / "iam.json", data)
    result = scan(app, "--iam-snapshot", export, fmt="sarif")
    assert result["runs"][0]["properties"]["authorizationEvaluated"] is False
    assert result["runs"][0]["properties"]["coverageStatus"] == "partial"
    saved = write_json(tmp_path / "saved.json", scan(app, "--iam-snapshot", export))
    result = CliRunner().invoke(main, ["report", str(saved), "--format", "sarif"])
    assert result.exit_code == 0
    assert (
        json.loads(result.stdout)["runs"][0]["properties"]["coverageStatus"]
        == "partial"
    )
