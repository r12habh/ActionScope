"""Shared pytest fixtures for ActionScope tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

_FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def cli_repo_safe(tmp_path: Path) -> Path:
    """Temporary copy of a repo with no AWS credential configuration."""
    repo = tmp_path / "safe"
    shutil.copytree(_FIXTURES_ROOT / "cli_repo_safe", repo)
    return repo


@pytest.fixture
def cli_repo_critical(tmp_path: Path) -> Path:
    """Temporary copy of a repo with OIDC + Terraform that yields CRITICAL risk."""
    repo = tmp_path / "critical"
    shutil.copytree(_FIXTURES_ROOT / "cli_repo_critical", repo)
    return repo
