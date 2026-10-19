"""Shared fixtures: scope files and a guard for the standard local lab target."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glassbox.scope import ScopeGuard


def write_scope(path: Path, **overrides: object) -> Path:
    """Write a scope JSON file with lab defaults, overridden per test."""
    data: dict[str, object] = {
        "engagement": "unit-tests",
        "authorized_by": "pytest",
        "allow": ["127.0.0.1", "localhost", "*.lab.example"],
        "deny": ["prod.lab.example"],
        "rate_limit_rps": 1000,  # tests run at full speed; politeness is tested separately
        "allow_mutations": False,
    }
    data.update(overrides)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    return write_scope(tmp_path / "scope.json")


@pytest.fixture
def guard(scope_file: Path) -> ScopeGuard:
    return ScopeGuard(scope_file)
