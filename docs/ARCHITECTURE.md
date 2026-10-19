# Architecture

## Data flow

```text
operator
   │  glassbox <cmd> <target> --scope <file>
   ▼
cli.py ── ScopeGuard(scope.py) ──┐
   │                             │ allow? (fail closed if scope file is
   │                             │   missing/malformed/empty; deny > allow)
   ▼                             ▼
module under test (exactly one network touchpoint per module)
   │
   │  Finding (frozen dataclass: rule_id, severity, target,
   │           description, evidence, remediation)
   ▼
report.py ──► deterministic Markdown / JSON
```

## Module contracts

| Module | Responsibility | Network access | Key invariant |
|---|---|---|---|
| `scope.py` | Allowlist decisions | none | fail closed; deny beats allow |
| `probe.py` | One HTTP GET + header/cookie/CORS audit + TLS facts | `requests.get`, TLS socket | `guard.check()` runs before any packet |
| `crawler.py` | BFS same-origin crawl, endpoint + parameter extraction | one `fetch()` per page (injectable) | off-site links recorded, never followed |
| `bust.py` | Wordlist content discovery + status classification | one `fetch()` per word (injectable) | delay = guard rate limit; errors are misses |
| `secrets.py` | 17 declarative regex rules over text/files | none | matches redacted before leaving the module |
| `report.py` | Professional report renderer (cover, exec summary, matrix, details) + JSON | none | sorted by severity -> rule_id -> target; same input = byte-equal output |
| `mcp_server.py` | MCP stdio server wrapping the tools above (Phase 4) | via the wrapped tools | scope pinned by `GLASSBOX_SCOPE` env (operator config), never a tool argument; no env = refuse |
| `cli.py` | Argument parsing, exit codes | none | every subcommand requires `--scope`; no bypass flag |

## Cross-cutting decisions

**One Finding type everywhere.** Probe findings and secret findings are the
same frozen dataclass, so reporting never branches on "where it came from".

**Injectable fetch.** `crawl()` and `bust()` accept a `fetch` callable; the
default wraps `requests.get`. Tests pass fakes, which is why the suite runs
offline in 0.85s and CI never touches a network.

**Rate limiting is data, not a constant.** Delay comes from the scope file's
`rate_limit_rps`, so politeness is part of the engagement record rather than
hardcoded in the loop.

**Severity is a closed set** (`info | low | medium | high`), validated in
`Finding.__post_init__`. No CVSS arithmetic: every score is a judgment this
project would have to defend, and the checklist is short enough to audit by eye.

**Determinism as a feature.** Reports sort by (severity, rule_id, target).
A retest overwrites the previous report with only real differences visible -
useful both in engagements and in code review.

## Layout

```text
src/glassbox/     core package (scope, probe, crawler, bust, secrets, report, cli)
tests/            57 offline tests; conftest.py builds scope fixtures
lab/mock_app.py   deliberately vulnerable demo target, 127.0.0.1 only
wordlists/        curated common.txt (~200 entries)
examples/         scope.example.json
docs/             spec, this file, scope policy
.github/workflows/  CI: ruff + pytest, Windows/Ubuntu x Python 3.11/3.12
```
