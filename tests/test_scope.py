"""Tests for the scope gate: allow, deny, wildcard edges, and fail-closed behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glassbox.scope import ScopeGuard, ScopeViolation
from tests.conftest import write_scope


def test_exact_host_allowed(guard: ScopeGuard) -> None:
    assert guard.check("127.0.0.1").allowed
    assert guard.check("http://127.0.0.1:8888/").allowed


def test_bare_localhost_allowed(guard: ScopeGuard) -> None:
    assert guard.check("localhost:8888").allowed


def test_subdomain_wildcard_matches(guard: ScopeGuard) -> None:
    assert guard.check("https://api.lab.example").allowed
    assert guard.check("https://deep.api.lab.example").allowed


def test_wildcard_does_not_match_apex(guard: ScopeGuard) -> None:
    """*.lab.example must NOT authorize the bare lab.example."""
    with pytest.raises(ScopeViolation, match="allowlist"):
        guard.check("https://lab.example")


def test_deny_wins_over_allow(guard: ScopeGuard) -> None:
    with pytest.raises(ScopeViolation, match="deny"):
        guard.check("https://prod.lab.example")


def test_unknown_host_denied(guard: ScopeGuard) -> None:
    with pytest.raises(ScopeViolation, match="allowlist"):
        guard.check("https://example.com")


def test_missing_scope_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ScopeViolation, match="Failing closed"):
        ScopeGuard(tmp_path / "nope.json")


def test_malformed_json_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "scope.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ScopeViolation, match="Failing closed"):
        ScopeGuard(bad)


def test_empty_allow_list_fails_closed(tmp_path: Path) -> None:
    empty = write_scope(tmp_path / "scope.json", allow=[])
    with pytest.raises(ScopeViolation, match="Failing closed"):
        ScopeGuard(empty)


def test_no_hostname_fails(tmp_path: Path, guard: ScopeGuard) -> None:
    with pytest.raises(ScopeViolation, match="hostname"):
        guard.check("   ")


def test_scope_file_rejects_non_list_deny(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"allow": ["localhost"], "deny": "oops"}), encoding="utf-8")
    with pytest.raises(ScopeViolation, match="deny"):
        ScopeGuard(path)


def test_properties_exposed(tmp_path: Path) -> None:
    path = write_scope(tmp_path / "scope.json", rate_limit_rps=5)
    guard = ScopeGuard(path)
    assert guard.rate_limit == 5.0
    assert guard.mutations_allowed is False
    assert guard.engagement == "unit-tests"
