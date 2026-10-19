# Glassbox Recon

Reconnaissance primitives in readable Python. No black boxes, no compiled
binaries, scope-gated by design.

[![CI](https://github.com/anggapbwr/glassbox-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/anggapbwr/glassbox-recon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-yellow.svg)](https://www.python.org/)

## Table of contents

- [Why this exists](#why-this-exists)
- [60-second quickstart](#60-second-quickstart)
- [Architecture](#architecture)
- [What this is NOT](#what-this-is-not)
- [Commands](#commands)
- [JSON output and exit codes](#json-output-and-exit-codes)
- [MCP server (call it from AI assistants)](#mcp-server-call-it-from-ai-assistants)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [License](#license)

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

Requirements:

- Python 3.11+
- pip
- Git
- A scope file (see `examples/scope.example.json`)

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

Install options:

- `pip install -e .` — install CLI only
- `pip install -e ".[dev]"` — include test/lint tooling
- `pip install -e ".[mcp]"` — include MCP server dependency

Real output from that command:

```text
probed http://127.0.0.1:8888/ -> 200 (21 ms, server=GlassboxLab/0.1 Python/3.14.5)
# Glassbox report - http://127.0.0.1:8888/

- Engagement: local-lab-demo
- Total findings: 7
- high: 0 | medium: 2 | low: 4 | info: 1

### [MEDIUM] header.csp.missing
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

### JSON output and exit codes

- Add `--json` on every command to produce machine-readable output.
- Scope violations return exit code `2` and no network request is sent.
- Successful scans return exit code `0` even if findings exist (findings are reported in output).
- Operational/runtime failures return non-zero exit codes.

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

## Troubleshooting

- **`refused: host ... is not in the engagement allowlist`**  
  Add the target host to your scope file only when you have written authorization.
- **MCP tools always refuse**  
  Ensure `GLASSBOX_SCOPE` points to a valid JSON scope file in your MCP client config.
- **`glassbox` command not found**  
  Re-activate the virtual environment, then reinstall with `pip install -e .`.
- **Tests failing locally**  
  Run from repo root and ensure dev dependencies are installed (`pip install -e ".[dev]"`).

## Contributing

Contributions are welcome for test coverage, rule improvements, and documentation.

1. Fork and create a feature branch.
2. Keep changes small and include/update tests.
3. Run `ruff check .`, `ruff format --check .`, and `pytest --cov=glassbox --cov-fail-under=85`.
4. Open a PR with clear scope, evidence, and any security considerations.

## Documentation

- [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md) - the locked build spec
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - module contracts and data flow
- [docs/SCOPE_POLICY.md](docs/SCOPE_POLICY.md) - authorization policy and refusal list

## License

[MIT](LICENSE). Authorized testing only - you are responsible for what you point
this at.
