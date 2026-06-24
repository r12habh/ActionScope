"""Tests for the GITHUB_TOKEN scope analyzer."""

from actionscope.analyzers.github_token import (
    KNOWN_PERMISSION_SCOPES,
    analyze_workflow_permissions,
    get_dangerous_token_permissions,
    summarize_token_risk,
)
from actionscope.models import RiskLevel

FULL_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def test_write_all_at_workflow_level_has_high_overall_risk() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": "write-all"},
        ".github/workflows/ci.yml",
    )

    summary = summarize_token_risk(perms)

    assert summary["has_write_all"] is True
    assert summary["overall_risk"] is RiskLevel.HIGH


def test_write_all_expands_known_scopes_at_workflow_level() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": "write-all"},
        ".github/workflows/ci.yml",
    )

    assert {permission.scope for permission in perms} == set(KNOWN_PERMISSION_SCOPES)
    assert {permission.job_name for permission in perms} == {""}
    assert {permission.risk_level for permission in perms} == {RiskLevel.HIGH}


def test_read_all_expands_to_low_risk_permissions() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": "read-all"},
        ".github/workflows/ci.yml",
    )

    assert len(perms) == len(KNOWN_PERMISSION_SCOPES)
    assert {permission.risk_level for permission in perms} == {RiskLevel.LOW}


def test_contents_write_is_medium() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {"contents": "write"}},
        ".github/workflows/ci.yml",
    )

    assert perms[0].scope == "contents"
    assert perms[0].risk_level is RiskLevel.MEDIUM


def test_pull_requests_write_is_high() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {"pull-requests": "write"}},
        ".github/workflows/ci.yml",
    )

    assert perms[0].scope == "pull-requests"
    assert perms[0].risk_level is RiskLevel.HIGH


def test_id_token_write_is_high_without_detected_oidc_consumer() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {"id-token": "write", "contents": "read"}},
        ".github/workflows/deploy.yml",
    )

    by_scope = {permission.scope: permission for permission in perms}

    assert by_scope["id-token"].risk_level is RiskLevel.HIGH
    assert by_scope["contents"].risk_level is RiskLevel.LOW


def test_id_token_write_with_aws_role_to_assume_is_info() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {"id-token": "write"},
            "jobs": {
                "deploy": {
                    "steps": [
                        {
                            "uses": "aws-actions/configure-aws-credentials@v4",
                            "with": {
                                "role-to-assume": (
                                    "arn:aws:iam::123456789012:role/ci-deploy"
                                )
                            },
                        }
                    ]
                }
            },
        },
        ".github/workflows/deploy.yml",
    )

    assert perms[0].risk_level is RiskLevel.INFO


def test_id_token_write_with_pypi_trusted_publishing_is_info() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {"id-token": "write"},
            "jobs": {
                "publish": {
                    "steps": [
                        {"uses": "pypa/gh-action-pypi-publish@release/v1"},
                    ]
                }
            },
        },
        ".github/workflows/release.yml",
    )

    assert perms[0].risk_level is RiskLevel.INFO


def test_id_token_write_with_sha_pinned_oidc_consumer_is_info() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {"id-token": "write"},
            "jobs": {
                "publish": {
                    "steps": [
                        {"uses": f"pypa/gh-action-pypi-publish@{FULL_SHA}"},
                    ]
                }
            },
        },
        ".github/workflows/release.yml",
    )

    assert perms[0].risk_level is RiskLevel.INFO


def test_id_token_write_with_npm_provenance_run_step_is_info() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {"id-token": "write"},
            "jobs": {
                "publish": {
                    "steps": [
                        {"run": "npm publish --provenance"},
                    ]
                }
            },
        },
        ".github/workflows/npm-release.yml",
    )

    assert perms[0].risk_level is RiskLevel.INFO


def test_id_token_write_with_github_pages_deploy_is_info() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {"id-token": "write"},
            "jobs": {
                "deploy": {
                    "steps": [
                        {"uses": "actions/deploy-pages@v5"},
                    ]
                }
            },
        },
        ".github/workflows/docs.yml",
    )

    assert perms[0].risk_level is RiskLevel.INFO


def test_id_token_write_with_vault_docker_or_snowflake_consumer_is_info() -> None:
    for action in (
        "hashicorp/vault-action@v3",
        "docker/login-action@v3",
        "snowflakedb/snowflake-cli-action@v1",
    ):
        perms = analyze_workflow_permissions(
            {
                "permissions": {"id-token": "write"},
                "jobs": {
                    "auth": {
                        "steps": [{"uses": action}],
                    }
                },
            },
            ".github/workflows/auth.yml",
        )

        assert perms[0].risk_level is RiskLevel.INFO


def test_id_token_write_with_non_aws_cloud_auth_is_info() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {"id-token": "write"},
            "jobs": {
                "deploy": {
                    "steps": [
                        {"uses": "google-github-actions/auth@v2"},
                        {"uses": "azure/login@v2"},
                    ]
                }
            },
        },
        ".github/workflows/cloud.yml",
    )

    assert perms[0].risk_level is RiskLevel.INFO


def test_job_level_id_token_calibration_is_scoped_to_same_job() -> None:
    perms = analyze_workflow_permissions(
        {
            "jobs": {
                "build": {
                    "permissions": {"id-token": "write"},
                    "steps": [{"run": "pytest"}],
                },
                "publish": {
                    "steps": [
                        {"uses": "pypa/gh-action-pypi-publish@release/v1"},
                    ]
                },
            }
        },
        ".github/workflows/release.yml",
    )

    assert perms[0].job_name == "build"
    assert perms[0].risk_level is RiskLevel.HIGH


def test_job_level_id_token_with_atlas_action_is_info() -> None:
    perms = analyze_workflow_permissions(
        {
            "jobs": {
                "atlas": {
                    "permissions": {"id-token": "write"},
                    "steps": [{"uses": "ariga/atlas-action@v1"}],
                },
            }
        },
        ".github/workflows/atlas-ci-public.yml",
    )

    assert perms[0].risk_level is RiskLevel.INFO


def test_job_level_id_token_with_slsa_reusable_workflow_is_info() -> None:
    perms = analyze_workflow_permissions(
        {
            "jobs": {
                "provenance": {
                    "permissions": {"id-token": "write"},
                    "uses": (
                        "slsa-framework/slsa-github-generator/"
                        ".github/workflows/generator_generic_slsa3.yml@v2.1.0"
                    ),
                },
            }
        },
        ".github/workflows/provenance.yml",
    )

    assert perms[0].risk_level is RiskLevel.INFO


def test_no_permissions_block_returns_empty_list() -> None:
    perms = analyze_workflow_permissions(
        {"jobs": {"test": {"steps": []}}},
        ".github/workflows/ci.yml",
    )

    assert perms == []


def test_job_level_override_captured_with_job_name() -> None:
    perms = analyze_workflow_permissions(
        {"jobs": {"deploy": {"permissions": {"contents": "read"}}}},
        ".github/workflows/deploy.yml",
    )

    assert len(perms) == 1
    assert perms[0].job_name == "deploy"
    assert perms[0].scope == "contents"


def test_job_override_includes_workflow_and_job_permissions() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {"contents": "write"},
            "jobs": {
                "deploy": {
                    "permissions": {"contents": "read"},
                }
            },
        },
        ".github/workflows/deploy.yml",
    )

    assert [(permission.job_name, permission.access) for permission in perms] == [
        ("", "write"),
        ("deploy", "read"),
    ]


def test_summarize_token_risk_has_pr_write_for_pull_requests_write() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {"pull-requests": "write"}},
        ".github/workflows/ci.yml",
    )

    assert summarize_token_risk(perms)["has_pr_write"] is True


def test_permissions_null_returns_empty_list() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": None},
        ".github/workflows/ci.yml",
    )

    assert perms == []


def test_permissions_empty_dict_returns_empty_list() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {}},
        ".github/workflows/ci.yml",
    )

    assert perms == []


def test_get_dangerous_token_permissions_returns_medium_or_higher() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {
                "contents": "write",
                "pull-requests": "write",
                "issues": "read",
            }
        },
        ".github/workflows/ci.yml",
    )

    dangerous = get_dangerous_token_permissions(perms)

    assert [permission.scope for permission in dangerous] == [
        "contents",
        "pull-requests",
    ]


def test_summarize_token_risk_sets_write_flags() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {
                "actions": "write",
                "contents": "write",
                "packages": "write",
            }
        },
        ".github/workflows/release.yml",
    )

    summary = summarize_token_risk(perms)

    assert summary["has_code_write"] is True
    assert summary["has_workflow_write"] is True
    assert summary["has_package_write"] is True
    assert summary["overall_risk"] is RiskLevel.HIGH
