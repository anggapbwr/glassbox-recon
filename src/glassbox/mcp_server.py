"""MCP server exposing Glassbox Recon primitives to AI assistants (Phase 4).

Scope policy design: the engagement scope file is pinned by the OPERATOR through
the ``GLASSBOX_SCOPE`` environment variable in the MCP client's server config -
never through a tool argument. An AI client calling these tools cannot widen the
allowlist, and with no env var set every tool refuses (fail closed, same
contract as the CLI).
"""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path

from .bust import bust as content_bust
from .bust import load_wordlist
from .crawler import crawl as crawl_site
from .probe import probe as http_probe
from .report import sort_findings
from .scope import ScopeGuard, ScopeViolation
from .secrets import scan_file

try:  # mcp 2.x: FastMCP was renamed to MCPServer
    from mcp.server.mcpserver import MCPServer
except ImportError:  # pragma: no cover - exercised only on mcp 1.x installs
    from mcp.server.fastmcp import FastMCP as MCPServer

MAX_CRAWL_DEPTH = 4
MAX_CRAWL_PAGES = 100
MAX_BUST_WORDS = 300

server = MCPServer(
    "glassbox-recon",
    instructions=(
        "Glassbox Recon: reconnaissance against AUTHORIZED targets only. Every "
        "network tool requires the operator's GLASSBOX_SCOPE allowlist; a "
        "refusal means the target is not authorized - do not retry with "
        "rewritten arguments. Secrets in findings are redacted by design."
    ),
)


def _guard() -> ScopeGuard:
    """Load the operator-pinned scope file; refuse when it is absent or invalid."""
    raw = os.environ.get("GLASSBOX_SCOPE", "").strip()
    if not raw:
        raise ScopeViolation(
            "GLASSBOX_SCOPE is not set. This server only runs with an "
            "operator-configured scope file: set it in the mcpServers env block "
            "of your client config."
        )
    return ScopeGuard(Path(raw))


@server.tool()
def validate_scope(url: str) -> dict:
    """Check whether a URL's host is in the operator's engagement allowlist.

    Read-only: no network request is made. Returns allowed=True/False with the
    reason, including when GLASSBOX_SCOPE is missing entirely.
    """
    try:
        decision = _guard().check(url)
    except ScopeViolation as exc:
        return {"url": url, "allowed": False, "reason": str(exc)}
    return {
        "url": url,
        "host": decision.host,
        "allowed": decision.allowed,
        "reason": decision.reason,
    }


@server.tool()
def probe(url: str) -> dict:
    """Fetch one URL and audit its response: status, security headers, cookie
    flags, CORS, and TLS certificate facts. Scope-checked; issues one GET only."""
    result = http_probe(url, _guard())
    payload = asdict(result)
    payload["findings"] = list(payload["findings"])  # asdict keeps tuples; JSON wants a list
    return payload


@server.tool()
def crawl(url: str, max_depth: int = 2, max_pages: int = 40) -> dict:
    """BFS-crawl one site (same host and its subdomains only) and return unique
    endpoints with their query/form parameter names. Depth and page caps are
    enforced server-side; off-site links are recorded, never followed."""
    result = crawl_site(
        url,
        _guard(),
        max_depth=max(0, min(max_depth, MAX_CRAWL_DEPTH)),
        max_pages=max(1, min(max_pages, MAX_CRAWL_PAGES)),
    )
    return {
        "seed": result.seed,
        "visited": len(result.visited),
        "endpoints": result.endpoints,
        "parameters": result.parameters,
        "skipped_offsite": len(result.skipped_offsite),
        "errors": result.errors,
    }


@server.tool()
def bust(url: str, wordlist: str | None = None) -> dict:
    """Content discovery: try common paths under an allowlisted base URL and
    classify what answers (200/401/403/redirect). Wordlist is capped
    server-side; rate limit comes from the operator's scope file."""
    words = load_wordlist(Path(wordlist) if wordlist else None)[:MAX_BUST_WORDS]
    discoveries = content_bust(url, _guard(), wordlist=words)
    return {"base_url": url, "hits": [asdict(d) for d in discoveries]}


@server.tool()
def secrets(path: str) -> dict:
    """Scan a LOCAL file for hardcoded credentials (AWS, GitHub, Slack, JWT,
    private keys, connection strings...). Evidence is always redacted; the
    caller never receives the matched value itself."""
    findings = scan_file(Path(path))
    return {
        "target": path,
        "count": len(findings),
        "findings": [asdict(f) for f in sort_findings(findings)],
    }


def main() -> None:
    """Console entry point ``glassbox-mcp``: serve over stdio."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
