# Contributing

Thanks for considering a contribution. This project values readable code and
verified behavior over feature volume.

## Ground rules

1. **Readable > clever.** Short functions, type hints on public APIs, docstrings
   that explain WHY. No metaprogramming, no dynamic imports.
2. **Every network path goes through `ScopeGuard`.** A contribution that opens a
   connection without a guard is rejected regardless of how useful it is.
3. **Tests are part of the change.** New behavior ships with pytest coverage
   (offline: inject `fetch` or mock `requests`; never live network in tests).
4. **Non-destructive by default.** GET/HEAD only; anything mutating must be
   opt-in and rate-limited.

## Workflow

1. Fork, branch from `main`: `git checkout -b feature/<short-name>`
2. Install dev deps: `pip install -e ".[dev]"` (add `.[mcp]` for server work)
3. Make the change with tests.
4. Gates (CI runs these on Windows + Ubuntu, Python 3.11/3.12):

   ```bash
   ruff check . && ruff format --check .
   pytest --cov=glassbox --cov-fail-under=85 -m "not integration"
   ```

5. Commit with conventional style: `feat(scope): ...`, `fix(cli): ...`,
   `docs(readme): ...`
6. Open a PR describing: what changed, why, how it was verified.

## Scope for contributions

Good fits: new audit checks with clear evidence, report improvements, platform
fixes, docs. Out of scope (see `docs/SCOPE_POLICY.md`): exploitation payloads,
DoS/flooding, authentication attacks, WAF evasion, scope-gate bypass flags.

## Reporting bugs

Open an issue with: OS + Python version, the exact command, expected vs actual
output. Never include real target data or credentials in an issue - redact
first, the way the tool itself does.
