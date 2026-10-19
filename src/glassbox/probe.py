"""HTTP probe and security-header audit.

`probe()` fetches one URL through the scope gate and records what the server
actually said: status, latency, redirect chain end, TLS certificate facts, and
header-based findings from `audit_headers()`.

The audit is a fixed checklist of common response-hardening headers. Each check
is one branch: presence, correct value, or a Finding. Deliberately boring code -
a reviewer should be able to verify every rule against the OWASP cheat sheet in
a single reading.
"""

from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlparse

import requests

from .scope import ScopeGuard

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "glassbox-recon/0.1 (+authorized testing only)"


@dataclass(frozen=True)
class Finding:
    """One confirmed observation. Immutable and JSON-serializable."""

    rule_id: str
    severity: str  # info | low | medium | high
    target: str
    description: str
    evidence: str
    remediation: str

    def __post_init__(self) -> None:
        if self.severity not in {"info", "low", "medium", "high"}:
            raise ValueError(f"invalid severity {self.severity!r}")


@dataclass(frozen=True)
class ProbeResult:
    """Everything one HTTP probe observed about a single URL."""

    url: str
    final_url: str
    status_code: int
    latency_ms: int
    server: str | None
    powered_by: str | None
    tls_subject: str | None
    tls_issuer: str | None
    tls_not_after: str | None
    findings: tuple[Finding, ...] = field(default_factory=tuple)


def _tls_cert_facts(
    host: str, port: int = 443, timeout: float = 5.0
) -> tuple[str | None, str | None, str | None]:
    """Read subject/issuer/expiry of the server certificate.

    Kept separate from probe() so a plain-HTTP probe never opens a socket here.
    Failures return Nones - a broken TLS handshake is reported by the HTTP layer,
    not silently swallowed into a wrong claim.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError):
        return None, None, None

    subject = dict(x[0] for x in cert.get("subject", ())).get("commonName")
    issuer_rdn = cert.get("issuer", ())
    issuer = dict(x[0] for x in issuer_rdn).get("commonName")
    not_after_raw = cert.get("notAfter")
    not_after = None
    if not_after_raw:
        try:
            timestamp = ssl.cert_time_to_seconds(not_after_raw)
            not_after = datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
        except (ValueError, OverflowError):
            not_after = not_after_raw  # keep the raw string rather than lose the fact
    return subject, issuer, not_after


def probe(url: str, guard: ScopeGuard, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """Fetch `url` (after the scope check) and summarize the response."""
    guard.check(url)  # raises ScopeViolation before any packet leaves the machine

    started = time.perf_counter()
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )
    latency_ms = int((time.perf_counter() - started) * 1000)

    parsed = urlparse(response.url)
    tls_subject = tls_issuer = tls_not_after = None
    if parsed.scheme == "https" and parsed.hostname:
        tls_subject, tls_issuer, tls_not_after = _tls_cert_facts(parsed.hostname)

    findings = tuple(audit_headers(response.headers, response.url))

    return ProbeResult(
        url=url,
        final_url=response.url,
        status_code=response.status_code,
        latency_ms=latency_ms,
        server=response.headers.get("Server"),
        powered_by=response.headers.get("X-Powered-By"),
        tls_subject=tls_subject,
        tls_issuer=tls_issuer,
        tls_not_after=tls_not_after,
        findings=findings,
    )


def audit_headers(headers: Mapping[str, str], target: str) -> list[Finding]:
    """Check response headers against a fixed hardening checklist.

    Returns findings for anything missing or misconfigured; a fully hardened
    response returns an empty list.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    def missing(rule_id: str, severity: str, header: str, why: str, fix: str) -> None:
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                target=target,
                description=f"Response is missing the {header} header. {why}",
                evidence=f"header {header!r} absent in response",
                remediation=fix,
            )
        )

    # HSTS: browsers will not pin this host to HTTPS without it.
    if "strict-transport-security" not in lower:
        missing(
            "header.hsts.missing",
            "low",
            "Strict-Transport-Security",
            "Browsers will not enforce HTTPS for this host.",
            "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        )

    # CSP: absence means the browser will execute whatever inline script the page feeds it.
    csp = lower.get("content-security-policy", "")
    if not csp:
        missing(
            "header.csp.missing",
            "medium",
            "Content-Security-Policy",
            "No policy constrains where scripts, frames, and assets may load from.",
            "Define a Content-Security-Policy starting with default-src 'self'.",
        )

    # MIME sniffing: X-Content-Type-Options must be exactly nosniff.
    xcto = lower.get("x-content-type-options", "")
    if xcto.lower() != "nosniff":
        missing(
            "header.xcto.missing",
            "low",
            "X-Content-Type-Options",
            "Browsers may MIME-sniff responses, e.g. treat an uploaded image as script.",
            "Send X-Content-Type-Options: nosniff.",
        )

    # Clickjacking: either X-Frame-Options, or frame-ancestors inside CSP.
    frame_ok = bool(lower.get("x-frame-options")) or "frame-ancestors" in csp
    if not frame_ok:
        missing(
            "header.xfo.missing",
            "medium",
            "X-Frame-Options",
            "The page can be framed by any origin (clickjacking risk).",
            "Send X-Frame-Options: DENY (or add frame-ancestors 'none' to CSP).",
        )

    # Version disclosure: Server/X-Powered-By with a version number aids fingerprinting.
    for header in ("server", "x-powered-by"):
        value = lower.get(header, "")
        if value and any(ch.isdigit() for ch in value) and "." in value:
            findings.append(
                Finding(
                    rule_id=f"header.{header}.version_disclosure",
                    severity="info",
                    target=target,
                    description=f"The {header} header discloses a software version.",
                    evidence=f"{header}: {value}",
                    remediation=f"Strip the version string from the {header} header.",
                )
            )

    # Cookies: Secure keeps them on HTTPS; HttpOnly keeps them out of JS.
    for header_value in (
        headers.get("Set-Cookie", "").split("\n") if "Set-Cookie" in headers else []
    ):
        _audit_cookie(header_value, target, findings)

    # CORS: wildcard origin combined with credentials is a classic over-permissive pair.
    acao = lower.get("access-control-allow-origin", "")
    acac = lower.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(
            Finding(
                rule_id="header.cors.wildcard_with_credentials",
                severity="high",
                target=target,
                description="CORS allows any origin WITH credentials - any site can read "
                "authenticated responses from this host.",
                evidence=f"Access-Control-Allow-Origin: * with Allow-Credentials: {acac}",
                remediation="Reflect only explicitly allowed origins; "
                "never combine * with credentials.",
            )
        )

    return findings


def _audit_cookie(set_cookie: str, target: str, findings: list[Finding]) -> None:
    """Flag session-ish cookies missing Secure or HttpOnly flags."""
    cookie = set_cookie.strip()
    if not cookie:
        return
    name = cookie.split("=", 1)[0].strip()
    lowered = cookie.lower()
    if "; secure" not in lowered:
        findings.append(
            Finding(
                rule_id="cookie.missing_secure",
                severity="low",
                target=target,
                description=f"Cookie {name!r} is sent over plain HTTP as well as HTTPS.",
                evidence=f"Set-Cookie: {name}=... (no Secure flag)",
                remediation="Add the Secure flag to the Set-Cookie header.",
            )
        )
    if "; httponly" not in lowered:
        findings.append(
            Finding(
                rule_id="cookie.missing_httponly",
                severity="low",
                target=target,
                description=f"Cookie {name!r} is readable from JavaScript (XSS can steal it).",
                evidence=f"Set-Cookie: {name}=... (no HttpOnly flag)",
                remediation="Add the HttpOnly flag to the Set-Cookie header.",
            )
        )
