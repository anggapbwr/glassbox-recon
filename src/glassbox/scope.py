"""Scope gate: the only path from a request to a network connection.

Every module that touches the network must hold a ScopeGuard. The guard reads an
engagement scope file (JSON allowlist) and denies anything not listed. A missing,
unreadable, or malformed scope file denies everything - fail closed, never open.

This module is deliberately plain Python: no LLM in the decision path, so the
answer to "may I talk to this host?" is always deterministic and auditable.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when a target is not covered by the engagement scope."""


@dataclass(frozen=True)
class ScopeDecision:
    """The outcome of one scope check, kept for logging and audit trails."""

    host: str
    allowed: bool
    reason: str


def _host_of(url_or_host: str) -> str:
    """Extract a lowercase hostname from a URL or a bare host string."""
    candidate = url_or_host.strip()
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}", scheme="")
    return (parsed.hostname or "").lower()


def _pattern_matches(pattern: str, host: str) -> bool:
    """Match an allowlist pattern against a host.

    `*.example.com` matches `a.example.com` but NOT the bare `example.com`:
    a wildcard covers subdomains only, never the apex domain itself.
    """
    pattern = pattern.lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base) and host != base
    if "*" in pattern or "?" in pattern or "[" in pattern:
        return fnmatch.fnmatch(host, pattern)
    return host == pattern


class ScopeGuard:
    """Allowlist engine backed by a JSON scope file.

    Expected file shape:
        {
          "engagement": "lab-demo",
          "authorized_by": "operator",
          "allow": ["127.0.0.1", "localhost", "*.lab.example"],
          "deny": ["prod.lab.example"],
          "rate_limit_rps": 5,
          "allow_mutations": false
        }

    `deny` always wins over `allow`.
    """

    def __init__(self, scope_path: Path) -> None:
        self._path = Path(scope_path)
        self._allow: list[str] = []
        self._deny: list[str] = []
        self._engagement = "unnamed"
        self._rate_limit_rps = 5.0
        self._allow_mutations = False
        self._load()

    def _load(self) -> None:
        """Read and validate the scope file. Any problem = deny everything."""
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScopeViolation(
                f"scope file missing or unreadable ({self._path}): {exc}. "
                "Failing closed: nothing is authorized without a valid scope file."
            ) from exc

        allow = raw.get("allow")
        if not isinstance(allow, list) or not allow:
            raise ScopeViolation(
                f"scope file {self._path} has no non-empty 'allow' list. Failing closed."
            )

        deny = raw.get("deny", [])
        if not isinstance(deny, list):
            raise ScopeViolation(f"scope file {self._path}: 'deny' must be a list.")

        self._allow = [str(p).lower() for p in allow]
        self._deny = [str(p).lower() for p in deny]
        self._engagement = str(raw.get("engagement", "unnamed"))
        self._rate_limit_rps = float(raw.get("rate_limit_rps", 5))
        self._allow_mutations = bool(raw.get("allow_mutations", False))

    @property
    def rate_limit(self) -> float:
        """Requests per second the operator allowed for this engagement."""
        return self._rate_limit_rps

    @property
    def mutations_allowed(self) -> bool:
        """Whether non-GET/HEAD requests are authorized (off by default)."""
        return self._allow_mutations

    @property
    def engagement(self) -> str:
        """Engagement name, for report headers."""
        return self._engagement

    def check(self, url_or_host: str) -> ScopeDecision:
        """Return a ScopeDecision, or raise ScopeViolation when denied."""
        host = _host_of(url_or_host)
        if not host:
            raise ScopeViolation(f"could not extract a hostname from {url_or_host!r}")

        deny_hit = next((p for p in self._deny if _pattern_matches(p, host)), None)
        if deny_hit:
            raise ScopeViolation(f"host {host} matches deny pattern {deny_hit!r}")

        allow_hit = next((p for p in self._allow if _pattern_matches(p, host)), None)
        if allow_hit:
            return ScopeDecision(
                host=host, allowed=True, reason=f"matched allow pattern {allow_hit!r}"
            )

        raise ScopeViolation(
            f"host {host} is not in the engagement allowlist ({self._path}). "
            "Add it to the scope file only if you hold written authorization."
        )
