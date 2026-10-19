# Antigravity Build Prompt — Glassbox Recon

Paste this file's content into Antigravity (Claude primary; switch to Gemini when
Claude hits its limit). Work strictly in order — Phases are sequential, each must be
committed before starting the next.

---

## ROLE & CONTEXT

You are building **Glassbox Recon**, a portfolio-grade reconnaissance toolkit in
Python. The full, locked specification is in `docs/PROJECT_SPEC.md` in this repository.
**Read it completely before writing any code.** It is the single source of truth —
do not invent features beyond it, do not "improve" the spec silently.

Repository root: `D:\GitHub\glassbox-recon` (Windows 11, git-bash available).
The GitHub remote is already configured.

## NON-NEGOTIABLE RULES (apply to every phase)

1. Runtime dependencies: only `requests` + `beautifulsoup4` (plus `pyyaml` if you use
   YAML scope files — prefer JSON scope files to avoid it). Dev deps: `pytest`,
   `pytest-cov`, `ruff`.
2. Every network-touching function requires a `ScopeGuard`; missing scope file means
   everything is denied (fail closed).
3. No live network calls in tests — mock HTTP with `unittest.mock` or a small fixture.
   Coverage floor 85% per module, enforced in CI.
4. Code style: obvious > clever. Short functions (< 40 lines), type hints on all public
   functions, module-level docstrings explaining WHY not WHAT.
5. After each phase: run `ruff check .` and `pytest` locally, fix everything, then
   `git add -A && git commit` with a clear conventional-commit message
   (e.g. `feat(scope): allowlist engine with wildcard matching`).
6. Never fabricate output. If something wasn't run, don't write it into docs.

## PHASE 0 — Scaffold

- Create the directory layout from PROJECT_SPEC.md §3 (empty modules with docstrings
  only), `pyproject.toml`, `LICENSE` (MIT, author: Aswangga Prabaswara),
  `.gitignore` (Python standard), `.github/workflows/ci.yml` (ruff + pytest matrix
  python 3.11/3.12 on windows-latest + ubuntu-latest).
- One trivial passing test so CI is green from day one.
- Commit.

## PHASE 1 — MVP (scope + probe + secrets)

Implement per PROJECT_SPEC.md §4.1–4.3 and the data model in §5:

- `src/glassbox/scope.py` — `ScopeGuard`, `ScopeDecision`, `ScopeViolation` exception,
  wildcard matching that does NOT match the bare domain, fail-closed on missing file.
- `src/glassbox/probe.py` — `probe()`, `audit_headers()`, full `ProbeResult` dataclass,
  all header-audit checks listed in the spec (each check = one Finding with stable
  rule_id like `header.hsts.missing`).
- `src/glassbox/secrets.py` — declarative rule table (~20 rules), `scan_text`,
  `scan_file`, redaction of matched secrets.
- `examples/scope.example.json` pointing at `127.0.0.1` and `localhost`.
- Tests: `tests/conftest.py` + `test_scope.py` + `test_probe.py` + `test_secrets.py`.
  Cover: wildcard edge cases, fail-closed behavior, every header audit rule fires on a
  crafted header dict, every secret rule matches its own synthetic sample, redaction works.
- Commit when green.

## PHASE 2 — Workflow (crawler, bust, report, cli)

- `crawler.py` — BFS same-origin crawl, depth-limited, rate-limit-aware, robots.txt
  respected by default, extracts links/forms/params/scripts.
- `bust.py` — wordlist content discovery with curated `wordlists/common.txt` (~200
  entries you write yourself), status/length classification, concurrency cap 5.
- `report.py` — deterministic markdown + JSON aggregation (sorted by severity, rule_id).
- `cli.py` — argparse commands `probe|secrets|crawl|bust`, all requiring `--scope`.
  Console entry point `glassbox` in pyproject.
- Tests for each; commit when green.

## PHASE 3 — Lab demo + docs

- `lab/mock_app.py` — Flask-free implementation preferred (stdlib `http.server`) to keep
  deps minimal; deliberate demo vulns: missing security headers, reflected parameter,
  fake leaked secret at `/debug/info`, insecure cookie. Bind 127.0.0.1:8888 only.
- Run the tool against the lab, capture the REAL output, and write `README.md`
  (< 200 lines: badges, 60-second quickstart, ASCII architecture diagram, scope-gate
  explanation, real demo output, "What this is NOT", MIT license).
- Write `docs/SCOPE_POLICY.md` per PROJECT_SPEC.md §7 and `docs/ARCHITECTURE.md`
  (module responsibilities + data flow diagram from the spec).
- Final commit, push to `main` (`git push origin main`).

## PHASE 4 (optional, only if asked again)

- `glassbox-mcp`: thin MCP server exposing probe/secrets/crawl tools. Separate prompt
  will be provided — do NOT start this phase unprompted.

## WHEN YOU HIT A LIMIT / ERROR

- If a command fails on Windows path handling, fix with `pathlib` — never hardcode
  separators.
- If a test needs the network, the test is wrong — mock it instead.
- If the spec is ambiguous, choose the simplest reading and note the decision in the
  commit message. Do not ask the user mid-phase for stylistic choices.
