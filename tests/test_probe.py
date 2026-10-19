"""Tests for the HTTP probe and header audit.

Network calls are mocked with unittest.mock so the suite runs offline: a test
that needs the internet is a broken test.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import glassbox.probe as probe_mod
from glassbox.probe import Finding
from glassbox.scope import ScopeViolation


def _response(
    headers: dict[str, str], status: int = 200, url: str = "http://127.0.0.1:8888/"
) -> MagicMock:
    resp = MagicMock()
    resp.headers = headers
    resp.status_code = status
    resp.url = url
    return resp


HARDENED = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Server": "nginx",
}


def rule_ids(findings: list[Finding] | tuple[Finding, ...]) -> set[str]:
    return {f.rule_id for f in findings}


def test_hardened_response_has_no_findings() -> None:
    assert probe_mod.audit_headers(HARDENED, "https://lab.example/") == []


def test_missing_headers_each_fire() -> None:
    findings = probe_mod.audit_headers({}, "http://x/")
    ids = rule_ids(findings)
    assert {
        "header.hsts.missing",
        "header.csp.missing",
        "header.xcto.missing",
        "header.xfo.missing",
    } <= ids


def test_frame_ancestors_in_csp_satisfies_frame_check() -> None:
    headers = dict(HARDENED)
    headers.pop("X-Frame-Options")
    findings = probe_mod.audit_headers(headers, "http://x/")
    assert "header.xfo.missing" not in rule_ids(findings)


def test_version_disclosure_info_finding() -> None:
    headers = dict(HARDENED) | {"Server": "Apache/2.4.57", "X-Powered-By": "PHP/8.2.1"}
    findings = probe_mod.audit_headers(headers, "http://x/")
    ids = rule_ids(findings)
    assert "header.server.version_disclosure" in ids
    assert "header.x-powered-by.version_disclosure" in ids
    disclosure = [f for f in findings if f.rule_id == "header.server.version_disclosure"]
    assert disclosure[0].severity == "info"
    assert "Apache/2.4.57" in disclosure[0].evidence


def test_cors_wildcard_with_credentials_is_high() -> None:
    headers = dict(HARDENED) | {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    findings = probe_mod.audit_headers(headers, "http://x/")
    cors = [f for f in findings if f.rule_id == "header.cors.wildcard_with_credentials"]
    assert len(cors) == 1
    assert cors[0].severity == "high"


def test_cors_wildcard_without_credentials_is_ok() -> None:
    headers = dict(HARDENED) | {"Access-Control-Allow-Origin": "*"}
    assert "header.cors.wildcard_with_credentials" not in rule_ids(
        probe_mod.audit_headers(headers, "http://x/")
    )


def test_cookie_flags_flagged() -> None:
    headers = dict(HARDENED) | {"Set-Cookie": "session=abc123; Path=/"}
    findings = probe_mod.audit_headers(headers, "http://x/")
    ids = rule_ids(findings)
    assert {"cookie.missing_secure", "cookie.missing_httponly"} <= ids


def test_cookie_with_both_flags_clean() -> None:
    headers = dict(HARDENED) | {"Set-Cookie": "session=abc123; Path=/; Secure; HttpOnly"}
    ids = rule_ids(probe_mod.audit_headers(headers, "http://x/"))
    assert "cookie.missing_secure" not in ids
    assert "cookie.missing_httponly" not in ids


def test_finding_rejects_bad_severity() -> None:
    with pytest.raises(ValueError, match="severity"):
        Finding(
            rule_id="x",
            severity="critical-plus",
            target="t",
            description="d",
            evidence="e",
            remediation="r",
        )


def test_probe_blocked_by_scope_before_any_request(guard) -> None:
    with patch.object(probe_mod.requests, "get") as mock_get:
        with pytest.raises(ScopeViolation):
            probe_mod.probe("https://example.com", guard)
        mock_get.assert_not_called()


def test_probe_happy_path(guard) -> None:
    with patch.object(
        probe_mod.requests, "get", return_value=_response(dict(HARDENED))
    ) as mock_get:
        result = probe_mod.probe("http://127.0.0.1:8888/", guard)
    mock_get.assert_called_once()
    assert result.status_code == 200
    assert result.final_url == "http://127.0.0.1:8888/"
    assert result.findings == ()
    assert result.latency_ms >= 0


def test_probe_insecure_target_produces_findings(guard) -> None:
    headers = {"Server": "Apache/2.4.1", "Set-Cookie": "sid=1"}
    with patch.object(probe_mod.requests, "get", return_value=_response(headers)):
        result = probe_mod.probe("http://127.0.0.1:8888/", guard)
    ids = rule_ids(result.findings)
    assert "cookie.missing_secure" in ids
    assert "header.csp.missing" in ids
