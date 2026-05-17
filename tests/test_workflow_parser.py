"""Tests for the GitHub Actions workflow parser."""

from pathlib import Path
from shutil import copyfile

from actionscope.parsers.workflow import (
    classify_action_ref,
    extract_aws_credential_sources,
    extract_env_var_references,
    find_unpinned_action_uses,
    find_workflow_files,
    is_pinned_to_sha,
    parse_workflow_file,
    scan_workflows,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "workflows"


def make_repo(tmp_path: Path, *fixture_names: str) -> Path:
    """Create a temporary repo with selected workflow fixtures."""
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    for fixture_name in fixture_names:
        copyfile(FIXTURE_DIR / fixture_name, workflow_dir / fixture_name)
    return tmp_path


def parse_fixture(fixture_name: str) -> dict:
    """Parse a workflow fixture and return its data."""
    workflow_data = parse_workflow_file(str(FIXTURE_DIR / fixture_name))
    assert workflow_data is not None
    return workflow_data


def test_find_workflow_files_returns_correct_paths_for_fixtures_dir(
    tmp_path: Path,
) -> None:
    repo = make_repo(
        tmp_path,
        "deploy_oidc.yml",
        "deploy_access_keys.yml",
        "multi_env.yml",
        "no_aws.yml",
    )

    files = find_workflow_files(str(repo))

    assert files == sorted(files)
    assert {Path(file).name for file in files} == {
        "deploy_oidc.yml",
        "deploy_access_keys.yml",
        "multi_env.yml",
        "no_aws.yml",
    }
    assert all(Path(file).is_absolute() for file in files)


def test_find_workflow_files_returns_empty_list_without_github_dir(
    tmp_path: Path,
) -> None:
    assert find_workflow_files(str(tmp_path)) == []


def test_parse_workflow_file_returns_none_for_invalid_yaml(
    tmp_path: Path,
    capsys,
) -> None:
    workflow_file = tmp_path / "broken.yml"
    workflow_file.write_text("jobs:\n  deploy: [", encoding="utf-8")

    assert parse_workflow_file(str(workflow_file)) is None
    assert "Warning:" in capsys.readouterr().err


def test_parse_workflow_file_returns_none_for_non_workflow_yaml(
    tmp_path: Path,
    capsys,
) -> None:
    workflow_file = tmp_path / "not-workflow.yml"
    workflow_file.write_text("name: Not a workflow\n", encoding="utf-8")

    assert parse_workflow_file(str(workflow_file)) is None
    assert "missing GitHub Actions" in capsys.readouterr().err


def test_parse_workflow_file_preserves_on_key() -> None:
    workflow_data = parse_fixture("deploy_oidc.yml")

    assert "on" in workflow_data
    assert True not in workflow_data


def test_extract_aws_credential_sources_finds_oidc_role() -> None:
    workflow_data = parse_fixture("deploy_oidc.yml")

    sources = extract_aws_credential_sources(workflow_data, "deploy_oidc.yml")

    assert len(sources) == 1
    assert sources[0].role_arn == (
        "arn:aws:iam::123456789012:role/github-deploy-role"
    )


def test_extract_aws_credential_sources_sets_uses_oidc_true() -> None:
    workflow_data = parse_fixture("deploy_oidc.yml")

    sources = extract_aws_credential_sources(workflow_data, "deploy_oidc.yml")

    assert sources[0].uses_oidc is True


def test_extract_aws_credential_sources_extracts_aws_region() -> None:
    workflow_data = parse_fixture("deploy_oidc.yml")

    sources = extract_aws_credential_sources(workflow_data, "deploy_oidc.yml")

    assert sources[0].aws_region == "us-east-1"


def test_extract_aws_credential_sources_sets_access_keys_true() -> None:
    workflow_data = parse_fixture("deploy_access_keys.yml")

    sources = extract_aws_credential_sources(
        workflow_data,
        "deploy_access_keys.yml",
    )

    assert len(sources) == 1
    assert sources[0].uses_access_keys is True
    assert sources[0].uses_oidc is False


def test_extract_aws_credential_sources_returns_empty_for_no_aws() -> None:
    workflow_data = parse_fixture("no_aws.yml")

    assert extract_aws_credential_sources(workflow_data, "no_aws.yml") == []


def test_multi_env_produces_two_aws_credential_sources() -> None:
    workflow_data = parse_fixture("multi_env.yml")

    sources = extract_aws_credential_sources(workflow_data, "multi_env.yml")

    assert len(sources) == 2
    assert {source.step_name for source in sources} == {
        "Configure deploy role",
        "Configure audit role",
    }


def test_scan_workflows_works_end_to_end_on_fixtures_dir(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        "deploy_oidc.yml",
        "deploy_access_keys.yml",
        "multi_env.yml",
        "no_aws.yml",
    )

    sources, token_permissions, unpinned_actions, errors = scan_workflows(str(repo))

    assert len(sources) == 4
    assert len(token_permissions) == 17
    assert len(unpinned_actions) == 4
    assert errors == []


def test_role_arn_correctly_extracted_from_with_block() -> None:
    workflow_data = parse_fixture("multi_env.yml")

    sources = extract_aws_credential_sources(workflow_data, "multi_env.yml")

    assert sources[1].role_arn == "${{ vars.AUDIT_ROLE_ARN }}"


def test_step_without_name_uses_uses_string_as_step_name() -> None:
    workflow_data = {
        "jobs": {
            "deploy": {
                "steps": [
                    {"uses": "aws-actions/configure-aws-credentials@v4"}
                ]
            }
        }
    }

    sources = extract_aws_credential_sources(workflow_data, "inline.yml")

    assert sources[0].step_name == "aws-actions/configure-aws-credentials@v4"


def test_workflow_without_permissions_block_has_empty_token_permissions(
    tmp_path: Path,
) -> None:
    repo = make_repo(tmp_path, "no_aws.yml")

    _, token_permissions, _, errors = scan_workflows(str(repo))

    assert token_permissions == []
    assert errors == []


def test_extract_env_var_references_returns_env_values() -> None:
    env_vars = extract_env_var_references(
        {"env": {"AWS_ACCESS_KEY_ID": "${{ secrets.AWS_KEY }}"}}
    )

    assert env_vars == {"AWS_ACCESS_KEY_ID": "${{ secrets.AWS_KEY }}"}


def test_env_access_key_marks_uses_access_keys_true() -> None:
    workflow_data = {
        "jobs": {
            "deploy": {
                "steps": [
                    {
                        "uses": "aws-actions/configure-aws-credentials@main",
                        "env": {
                            "AWS_ACCESS_KEY_ID": "${{ secrets.AWS_ACCESS_KEY_ID }}"
                        },
                    }
                ]
            }
        }
    }

    sources = extract_aws_credential_sources(workflow_data, "inline.yml")

    assert sources[0].uses_access_keys is True


def test_step_without_with_block_returns_source_with_no_role() -> None:
    workflow_data = {
        "jobs": {
            "deploy": {
                "steps": [
                    {"uses": "aws-actions/configure-aws-credentials@abcdef"}
                ]
            }
        }
    }

    sources = extract_aws_credential_sources(workflow_data, "inline.yml")

    assert sources[0].role_arn is None
    assert sources[0].uses_access_keys is False


def test_scan_workflows_records_parse_errors(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "broken.yml").write_text("jobs:\n  deploy: [", encoding="utf-8")

    sources, token_permissions, unpinned_actions, errors = scan_workflows(str(tmp_path))

    assert sources == []
    assert token_permissions == []
    assert unpinned_actions == []
    assert len(errors) == 1


def test_job_level_id_token_permission_sets_uses_oidc_true() -> None:
    workflow_data = parse_fixture("multi_env.yml")

    sources = extract_aws_credential_sources(workflow_data, "multi_env.yml")

    assert all(source.uses_oidc is True for source in sources)


def test_is_pinned_to_sha_returns_true_for_full_sha() -> None:
    assert is_pinned_to_sha(
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
    )


def test_is_pinned_to_sha_returns_false_for_tag() -> None:
    assert is_pinned_to_sha("actions/checkout@v4") is False


def test_is_pinned_to_sha_returns_false_for_branch() -> None:
    assert is_pinned_to_sha("actions/checkout@main") is False


def test_is_pinned_to_sha_returns_true_for_local_action() -> None:
    assert is_pinned_to_sha("./.github/actions/setup")


def test_classify_action_ref_returns_tag_for_version_tag() -> None:
    assert classify_action_ref("actions/checkout@v4") == "tag"


def test_classify_action_ref_returns_branch_for_main() -> None:
    assert classify_action_ref("actions/checkout@main") == "branch"


def test_classify_action_ref_returns_sha_for_full_sha() -> None:
    assert (
        classify_action_ref(
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
        )
        == "sha"
    )


def test_classify_action_ref_returns_local_for_relative_path() -> None:
    assert classify_action_ref("./action") == "local"


def test_find_unpinned_action_uses_returns_empty_for_sha_pinned_workflow() -> None:
    workflow_data = {
        "jobs": {
            "test": {
                "steps": [
                    {
                        "name": "Checkout",
                        "uses": (
                            "actions/checkout@"
                            "11bd71901bbe5b1630ceea73d27597364c9af683"
                        ),
                    },
                    {"uses": "./.github/actions/local"},
                ]
            }
        }
    }

    assert find_unpinned_action_uses(workflow_data, "ci.yml") == []


def test_find_unpinned_action_uses_finds_v4_tags_as_unpinned() -> None:
    workflow_data = {
        "jobs": {
            "deploy": {
                "steps": [
                    {"name": "Checkout", "uses": "actions/checkout@v4"}
                ]
            }
        }
    }

    findings = find_unpinned_action_uses(workflow_data, "deploy.yml")

    assert len(findings) == 1
    assert findings[0]["uses"] == "actions/checkout@v4"
    assert findings[0]["pin_type"] == "tag"
