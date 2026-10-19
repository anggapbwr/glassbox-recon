# Glassbox Recon

Reconnaissance primitives in readable Python. No black boxes, no compiled
binaries, scope-gated by design.

[![CI](https://github.com/anggapbwr/glassbox-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/anggapbwr/glassbox-recon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-yellow.svg)](https://www.python.org/)

## Why this exists

Most recon frameworks wrap compiled binaries you cannot read. This one is the
opposite: every byte that crosses the network traces back to a short, testable
Python function. The whole codebase reads in under an hour, and every finding
it reports carries the evidence that produced it.

Three design commitments:

1. **The scope gate is architecture, not documentation.** No module opens a
   connection without `ScopeGuard` checking an allowlist first. A missing or
   broken scope file denies everything (fail closed). There is no
   `--force` / `--ignore-scope` flag: the fix belongs in the scope file.
2. **Evidence over claims.** Findings are immutable records of what a response
   actually contained. Secrets are redacted in reports (`ghp_...5678`), so the
   tool's output never becomes its own leak.
3. **Tests prove behavior offline.** 57 tests, 91% coverage, HTTP mocked - CI
   never touches the network.

## 60-second quickstart

```bash
git clone https://github.com/anggapbwr/glassbox-recon.git
cd glassbox-recon
python -m venv .venv && .venv/Scripts/activate     # .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
pytest                                             # 57 passed
```

Run the bundled vulnerable lab (127.0.0.1:8888 only) and scan it:

```bash
python lab/mock_app.py                             # terminal 1
glassbox probe http://127.0.0.1:8888/ --scope examples/scope.example.json
```

Real output from that command:

```text
probed http://127.0.0.1:8888/ -> 200 (21 ms, server=GlassboxLab/0.1 Python/3.14.5)
# Security Assessment Report

| Field | Value |
|---|---|
| Engagement | local-lab-demo |
| Target | http://127.0.0.1:8888/ |
| Assessment type | Automated reconnaissance & configuration audit |
| Tool | glassbox-recon 0.1.0 |
| Generated (UTC) | 2026-10-19T07:11:12+00:00 |
| Classification | CONFIDENTIAL - for the assessed party only |

## 1. Executive Summary

**7 findings** were confirmed: 0 high, 2 medium, 4 low, 1 info.

Overall risk posture: **MODERATE**.

## 2. Findings Summary

| ID | Severity | Rule | Target |
|---|---|---|---|
| F-001 | MEDIUM | header.csp.missing | `http://127.0.0.1:8888/` |
| F-002 | MEDIUM | header.xfo.missing | `http://127.0.0.1:8888/` |
| ... | ... | ... | ... |

### F-001 [MEDIUM] header.csp.missing
- Evidence: `header 'Content-Security-Policy' absent in response`
...
```

Out-of-scope targets are refused before any request is sent:

```text
$ glassbox probe https://example.com/ --scope examples/scope.example.json
refused: host example.com is not in the engagement allowlist. Add it to the
scope file only if you hold written authorization.
(exit code 2)
```

## Architecture

```text
                    ┌──────────────────────────────────────────┐
   CLI (cli.py) ───►│  ScopeGuard (scope.py)  - fail closed    │
                    │  allow/deny patterns, rate limit        │
                    └───────────────┬──────────────────────────┘
                                    │  only then may I/O happen
          ┌──────────────┬──────────┼───────────┬──────────────┐
          ▼              ▼          ▼           ▼              │
     probe.py        crawler.py  bust.py    secrets.py         │
   (header audit)  (BFS, same-  (wordlist  (regex rules,       │
                    origin)     discovery)  redacted output)   │
          │              │          │           │              │
          └──────────────┴────┬─────┴───────────┘              │
                              ▼                                │
                       report.py                               │
              deterministic Markdown / JSON (sorted, diffable) │
```

- `probe()` - fetch one URL, audit 8 header/cookie/CORS hardening checks,
  record TLS certificate facts.
- `crawl()` - BFS with depth/page caps, collects endpoints + parameter names,
  skips off-site links, injected `fetch` (tests never hit the network).
- `bust()` - content discovery against a bundled 200-entry wordlist;
  classifies 401/403/redirects instead of just printing status codes.
- `secrets()` - 17 declarative regex rules (AWS, GitHub, Slack, Stripe, JWT,
  PEM blocks, connection strings, ...), every rule proven by a synthetic sample
  in `tests/test_secrets.py`.
- `report()` - findings sorted by severity then rule id: same input, byte-equal
  output, so retest diffs are clean.

## What this is NOT

- Not an exploit tool. Recon primitives only: no payloads, no DoS, no
  credential stuffing, no WAF evasion.
- Not a scanner for third-party targets. See
  [docs/SCOPE_POLICY.md](docs/SCOPE_POLICY.md) - the tool assumes you hold
  written authorization and the scope file is how you prove it to the code.
- Not faster than ffuf/nuclei/subfinder, and not trying to be. Readability and
  auditability are the features.

## Commands

```text
glassbox probe  <url>  --scope <file> [--json]   header audit + TLS facts
glassbox crawl  <url>  --scope <file> [--json] [--max-depth N] [--max-pages N]
glassbox bust   <url>  --scope <file> [--json] [--wordlist <file>]
glassbox secrets <path> --scope <file> [--json]  credential scan of a file
```

## MCP server (call it from AI assistants)

Phase 4 exposes the same primitives over MCP (stdio) so Claude Desktop, Cursor,
Hermes, or any MCP client can call them:

```bash
pip install -e ".[mcp]"        # adds the `mcp` SDK + glassbox-mcp entry point
```

```json
{
  "mcpServers": {
    "glassbox": {
      "command": "glassbox-mcp",
      "env": { "GLASSBOX_SCOPE": "C:/path/to/scope.json" }
    }
  }
}
```

Tools: `probe`, `crawl`, `bust`, `secrets`, `validate_scope`.

Design note: the scope file is pinned by **the operator** through
`GLASSBOX_SCOPE` in the client config - it is never a tool argument, so an AI
calling these tools cannot widen the allowlist. No env var = every tool
refuses (fail closed, same contract as the CLI).

## Development

```bash
pytest --cov=glassbox --cov-fail-under=85   # coverage floor enforced in CI
ruff check . && ruff format --check .       # lint + format gates
```

CI runs both gates on Windows and Ubuntu, Python 3.11 and 3.12.

## Documentation

- [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md) - the locked build spec
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - module contracts and data flow
- [docs/SCOPE_POLICY.md](docs/SCOPE_POLICY.md) - authorization policy and refusal list
- [docs/BUILD_LOG.md](docs/BUILD_LOG.md) - why it exists, design decisions, engineering lessons
- [docs/BUGBOUNTY_WORKFLOW.md](docs/BUGBOUNTY_WORKFLOW.md) - using the tool inside a real program
- [templates/report_template.md](templates/report_template.md) - branded assessment report skeleton (PDF-ready via pandoc)

## License

[MIT](LICENSE). Authorized testing only - you are responsible for what you point
this at.
