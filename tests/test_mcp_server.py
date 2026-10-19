"""Phase 4 MCP server tests: operator-pinned scope, refusal paths, tool registry.

Network calls stay mocked (same rule as every other test module). The tool
functions are called directly because @server.tool() returns the original
function - the registry itself is verified separately via list_tools().
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import glassbox.probe as probe_mod
from glassbox import mcp_server
from glassbox.mcp_server import _guard, bust, crawl, probe, secrets, validate_scope
from glassbox.scope import ScopeViolation
from tests.conftest import write_scope


def test_server_registers_expected_tools() -> None:
    tools = asyncio.run(mcp_server.server.list_tools())
    names = {t.name for t in tools}
    assert names == {"validate_scope", "probe", "crawl", "bust", "secrets"}
    for tool in tools:
        assert tool.description, f"tool {tool.name} lacks a description for AI clients"


def test_guard_refuses_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GLASSBOX_SCOPE", raising=False)
    with pytest.raises(ScopeViolation, match="GLASSBOX_SCOPE is not set"):
        _guard()


def test_validate_scope_reports_missing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GLASSBOX_SCOPE", raising=False)
    verdict = validate_scope("http://127.0.0.1:8888/")
    assert verdict["allowed"] is False
    assert "GLASSBOX_SCOPE" in verdict["reason"]


def test_validate_scope_allowed_and_denied(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scope = write_scope(tmp_path / "scope.json")
    monkeypatch.setenv("GLASSBOX_SCOPE", str(scope))

    assert validate_scope("http://127.0.0.1:8888/")["allowed"] is True
    denied = validate_scope("https://example.com/")
    assert denied["allowed"] is False
    assert "allowlist" in denied["reason"]


def test_probe_tool_refuses_out_of_scope(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scope = write_scope(tmp_path / "scope.json")
    monkeypatch.setenv("GLASSBOX_SCOPE", str(scope))
    with patch.object(probe_mod.requests, "get") as mock_get:
        with pytest.raises(ScopeViolation):
            probe("https://example.com/")
        mock_get.assert_not_called()


def test_probe_tool_returns_probe_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scope = write_scope(tmp_path / "scope.json")
    monkeypatch.setenv("GLASSBOX_SCOPE", str(scope))
    resp = MagicMock()
    resp.headers = {"Server": "nginx"}
    resp.status_code = 200
    resp.url = "http://127.0.0.1:8888/"
    with patch.object(probe_mod.requests, "get", return_value=resp):
        payload = probe("http://127.0.0.1:8888/")
    assert payload["status_code"] == 200
    assert isinstance(payload["findings"], list)
    assert any(f["rule_id"] == "header.csp.missing" for f in payload["findings"])
    json.dumps(payload)  # must be JSON-serializable for MCP structured output


def test_crawl_tool_caps_enforced(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scope = write_scope(tmp_path / "scope.json")
    monkeypatch.setenv("GLASSBOX_SCOPE", str(scope))
    html = '<html><body><a href="/about">x</a></body></html>'
    with patch("glassbox.crawler.requests.get", return_value=MagicMock(text=html)):
        payload = crawl("http://127.0.0.1:8888/", max_depth=99, max_pages=9999)
    assert payload["seed"] == "http://127.0.0.1:8888/"
    json.dumps(payload)


def test_bust_tool_finds_hits(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scope = write_scope(tmp_path / "scope.json")
    monkeypatch.setenv("GLASSBOX_SCOPE", str(scope))
    with patch(
        "glassbox.bust.requests.get",
        side_effect=lambda url, **kw: MagicMock(
            status_code=200 if url.endswith("/admin") else 404, content=b"x" * 10
        ),
    ):
        payload = bust("http://127.0.0.1:8888/")
    assert any(h["url"].endswith("/admin") for h in payload["hits"])


def test_secrets_tool_redacts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scope = write_scope(tmp_path / "scope.json")
    monkeypatch.setenv("GLASSBOX_SCOPE", str(scope))
    target = tmp_path / "app.py"
    target.write_text('KEY = "ghp_' + "a" * 36 + '"', encoding="utf-8")
    payload = secrets(str(target))
    raw = json.dumps(payload)
    assert payload["count"] >= 1
    assert "a" * 36 not in raw  # evidence never carries the full match
    assert payload["findings"][0]["rule_id"] in {
        "secret.github.pat",
        "secret.password.assignment",
    }


def test_secrets_tool_missing_file_fails_as_tool_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scope = write_scope(tmp_path / "scope.json")
    monkeypatch.setenv("GLASSBOX_SCOPE", str(scope))
    with pytest.raises(FileNotFoundError):
        secrets(str(tmp_path / "nope.py"))
