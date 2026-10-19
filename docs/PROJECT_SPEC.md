# Glassbox Recon — Project Specification (Final)

Status: locked spec v1.0 — implement against this document.
Repo: https://github.com/anggapbwr/glassbox-recon
License: MIT

## 1. Vision

A reconnaissance toolkit written to be **read, tested, and understood** — the opposite of
black-box frameworks that wrap compiled binaries. Every byte that crosses the network can
be traced to a readable Python source file in this repository.

Positioning line (for README):

> Glassbox Recon — reconnaissance primitives in readable Python.
> No black boxes. No compiled binaries. Scope-gated by design.

This is a portfolio project. Its value proposition is engineering quality, not feature
count: clean architecture, real tests, CI, honest documentation.

## 2. Design Principles (non-negotiable)

1. **Readability first.** Any reviewer must understand the whole codebase in under one
   hour. Prefer obvious code over clever code. No metaprogramming, no dynamic imports,
   no hidden control flow.
2. **Stdlib-first.** Runtime dependencies limited to: `requests`, `beautifulsoup4`.
   No compiled extensions, no Go binaries, no subprocess calls to external scanners.
3. **Scope gate by design.** No module may open a network connection to a target without
   a `ScopeGuard` that validated the host against the engagement allowlist. The gate is
   plain Python (LLM-free, deterministic) and lives in `glassbox/scope.py`.
4. **Non-destructive by default.** Only GET/HEAD are used by default. Mutating requests
   (POST/PUT) are opt-in, capped, and rate-limited.
5. **Tested.** Every module ships with pytest tests using mocked HTTP (no live network
   in the test suite). Coverage floor: 85% per module.
6. **Windows-first, cross-platform.** Developed and documented on Windows 11; must also
   run on Linux/macOS. No POSIX-only assumptions (path handling via `pathlib`).
7. **Honest output.** Findings record what was actually observed, never speculation.
   A module that fails must say so; it must never return fabricated data.

## 3. Repository Layout

```
glassbox-recon/
├── README.md                  # written LAST, from real runs only
├── LICENSE                    # MIT
├── pyproject.toml             # deps: requests, beautifulsoup4; dev: pytest, ruff, coverage
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml             # ruff check + pytest (matrix: windows-latest, ubuntu-latest)
├── src/
│   └── glassbox/
│       ├── __init__.py        # __version__, public exports
│       ├── scope.py           # ScopeGuard: allowlist engine, ROE config
│       ├── probe.py           # HTTP probe + security header audit
│       ├── secrets.py         # regex-based credential scanner
│       ├── crawler.py         # same-origin crawler, endpoint/param miner      [phase 2]
│       ├── bust.py            # content discovery (wordlist dir busting)        [phase 2]
│       ├── report.py          # findings aggregator: markdown + JSON output     [phase 2]
│       └── cli.py             # argparse CLI: glassbox <command>                [phase 2]
├── lab/
│   └── mock_app.py            # small Flask app with deliberate vulns (demo)    [phase 3]
├── tests/
│   ├── conftest.py            # shared fixtures (mock responses, temp scope files)
│   ├── test_scope.py
│   ├── test_probe.py
│   └── test_secrets.py
├── examples/
│   └── scope.example.yaml     # sample engagement scope file
└── docs/
    ├── ARCHITECTURE.md        # module responsibilities + data flow
    ├── SCOPE_POLICY.md        # authorization policy, what this tool refuses to do
    └── ROADMAP.md
```

## 4. Modules

### 4.1 `scope.py` — the gate (Phase 1)

Data model — engagement scope file (`scope.yaml`, but parsed as plain YAML-subset or JSON
to keep deps minimal; decision: use JSON `scope.json` if avoiding a YAML dependency,
otherwise `pyyaml` is allowed as a third runtime dep):

```json
{
  "engagement": "lab-demo",
  "authorized_by": "operator",
  "allow": ["127.0.0.1", "localhost", "*.lab.example"],
  "deny": ["prod.example.com"],
  "rate_limit_rps": 5,
  "allow_mutations": false
}
```

Public API:

```python
class ScopeGuard:
    def __init__(self, scope_path: Path): ...
    def check(self, url_or_host: str) -> ScopeDecision   # raises ScopeViolation on deny
    @property
    def rate_limit(self) -> float
    @property
    def mutations_allowed(self) -> bool

@dataclass(frozen=True)
class ScopeDecision:
    host: str
    allowed: bool
    reason: str
```

Rules:
- Wildcard subdomain matching (`*.example.com`) must NOT match the bare domain.
- IP addresses are matched exactly; CIDR support is out of scope for v1.
- A missing/unreadable scope file = everything denied (fail closed, never open).
- Every denial is logged with host + reason.

### 4.2 `probe.py` — HTTP probe + header audit (Phase 1)

```python
def probe(url: str, guard: ScopeGuard, timeout: float = 10.0) -> ProbeResult
def audit_headers(response_headers: dict) -> list[Finding]
```

`ProbeResult` captures: final URL (after redirects), status code, latency, server/
powered-by headers, detected tech hints, TLS certificate subject + issuer + expiry,
cookie flags (HttpOnly/Secure/SameSite).

Header audit checks (each produces a `Finding` with severity `info`/`low`/`medium`):
- missing `Strict-Transport-Security`
- missing/weak `Content-Security-Policy`
- missing `X-Content-Type-Options`
- missing `X-Frame-Options` / frame-ancestors in CSP
- `Server` / `X-Powered-By` version disclosure
- cookies missing `Secure` or `HttpOnly`
- CORS: `Access-Control-Allow-Origin: *` combined with `Allow-Credentials: true`

Severity scale is deliberately small: `info | low | medium | high` (no CVSS math in v1).

### 4.3 `secrets.py` — credential scanner (Phase 1)

```python
def scan_text(text: str) -> list[Finding]
def scan_file(path: Path) -> list[Finding]
```

- Regex rules in a single declarative table at the top of the file — each rule: id,
  description, severity, compiled regex. Target ~20 rules in v1 (AWS keys, GitHub PAT,
  Slack tokens, JWT, private key blocks, generic `password=`/`api_key=`, Google API key,
  Stripe key, SendGrid, Twilio, Bearer tokens). Rules must be reviewable at a glance.
- Matched secrets are **redacted** in findings (`AKIA…7H2Q`), never printed in full.
- No entropy-based detection in v1 (keeps behavior explainable); noted as future work.

### 4.4 `crawler.py` — same-origin crawler (Phase 2)

- BFS from a seed URL, same registrable domain only, depth-limited (default 2).
- Extracts: links, forms (method + action + input names), script srcs, query parameters.
- Politeness: honors `guard.rate_limit`, sends a custom `User-Agent: glassbox-recon/<ver>`,
  stops on `robots.txt` Disallow by default (flag to disable for authorized targets).
- Output: `CrawlResult` with unique endpoints + parameters set.

### 4.5 `bust.py` — content discovery (Phase 2)

- Wordlist-driven path guessing (ships with a small curated `common.txt`, ~200 entries).
- Classifies by status code + content length; reports non-404 with length deltas.
- Hard concurrency cap (default 5) and rate limit from scope.

### 4.6 `report.py` + `cli.py` (Phase 2)

- `report.py`: renders a professional assessment report (cover block with
  classification, executive summary with risk posture, findings matrix with
  F-IDs, detailed findings, methodology, scope & limitations, disclaimer) plus a
  JSON variant for automation. Output is deterministic (sorted by severity then
  rule id) so retests diff cleanly in git. A brandable PDF-ready skeleton lives
  in `templates/report_template.md`.
- `cli.py` commands: `glassbox probe <url>`, `glassbox secrets <path>`,
  `glassbox crawl <url>`, `glassbox bust <url>`, all requiring `--scope <file>`.
  No scope flag = command refuses to run.

### 4.7 `lab/mock_app.py` (Phase 3)

Small Flask app with deliberate, safe local-only vulnerabilities for demos:
missing security headers, a reflected parameter (XSS demo), a debug endpoint leaking a
fake secret, an insecure cookie. Binds to 127.0.0.1 only. Used to record the README demo
and as a live integration test target (marked `@pytest.mark.integration`, off by default).

## 5. Data Model

```python
@dataclass(frozen=True)
class Finding:
    rule_id: str  # e.g. "header.hsts.missing"
    severity: str  # info | low | medium | high
    target: str  # URL or file path the finding came from
    description: str  # what was observed
    evidence: str  # redacted, reproducible snippet (header line, redacted token)
    remediation: str  # short fix hint
```

Findings are immutable and JSON-serializable. Nothing else crosses module boundaries.

## 6. Quality Gates (CI)

`.github/workflows/ci.yml`:
- `ruff check .` and `ruff format --check .`
- `pytest --cov=glassbox --cov-fail-under=85` on `windows-latest` AND `ubuntu-latest`
- Python matrix: 3.11, 3.12
- No live-network tests in CI. Integration tests are opt-in via marker.

## 7. Scope / Ethics Policy (docs/SCOPE_POLICY.md)

- The tool is for authorized testing only (own systems, lab, bug bounty with written scope).
- The scope gate cannot be bypassed by flags; the only way to scan a host is to put it
  in the allowlist.
- Documented refusal list: no exploitation payloads, no DoS/flooding, no auth bypass
  automation, no evasion modules. Recon primitives only.
- This policy file is a feature of the portfolio: it demonstrates professional judgment.

## 8. Phases & Acceptance Criteria

**Phase 0 — scaffold**: layout, pyproject, CI green on empty test, LICENSE, .gitignore.
**Phase 1 — MVP**: scope.py + probe.py + secrets.py + full tests + examples/scope.example.json.
Acceptance: `pytest` green locally and in CI on both OSes; a real run against
`http://127.0.0.1:8888` (lab) produces findings; a run against a non-allowlisted host
raises `ScopeViolation`.
**Phase 2 — workflow**: crawler.py, bust.py, report.py, cli.py + docs.
Acceptance: `glassbox probe <lab-url> --scope examples/scope.example.json` prints a
deterministic markdown report.
**Phase 3 — demo**: lab/mock_app.py + recorded demo section in README + SCOPE_POLICY.md.
**Phase 4 (optional)**: `glassbox-mcp` - thin MCP server exposing probe/secrets/crawl/bust/validate_scope as
tools for AI assistants. Only after Phases 0-3 are done.
> **Status: implemented.** `src/glassbox/mcp_server.py` (mcp SDK v2 `MCPServer`, stdio,
> 5 tools), tests in `tests/test_mcp_server.py`, entry point `glassbox-mcp`, scope pinned
> via `GLASSBOX_SCOPE` env (never a tool argument).

## 9. README Rules (enforce in Phase 3)

- Every code block in README must come from a real executed run — no invented output.
- Include: badge row (CI, license, python versions), 60-second quickstart,
  architecture diagram (ASCII), scope-gate explanation, demo against the local lab,
  "What this is NOT" section, license.
- Length target: under 200 lines.
