"""Fixtures for the agent-ooda declarative tests (Hermes OODA direct-to-Kali profile).

Resolve the paths of the files to parse RELATIVE to the worktree root (two levels
above this file: agent-ooda/tests/ -> root), so `pytest agent-ooda/tests/`
works from the repo root without depending on the cwd.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# agent-ooda/tests/conftest.py -> parents[2] = worktree root.
_REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return _REPO_ROOT


@pytest.fixture(scope="session")
def profile_config_path(repo_root: Path) -> Path:
    return repo_root / "agent-ooda" / "profile" / "config.yaml"


@pytest.fixture(scope="session")
def compose_path(repo_root: Path) -> Path:
    return repo_root / "docker-compose.yml"
