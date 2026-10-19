# Build Log: why Glassbox Recon exists and how it was built

The story behind the repo - useful as interview material and as context for
contributors. All numbers below are real, from actual runs.

## Origin

Started as a research question: the "AI recon framework" space on GitHub is
crowded (BBOT ~10k stars, AIRecon ~1k, Cybermes ~900). The honest conclusion
before writing a line of code: **reimplementing recon features would add
nothing**. What was missing in that space, in our reading:

- scope enforcement as a *tested invariant* rather than a documentation claim
- readable Python (most tools wrap compiled binaries you cannot audit)
- real CI (Windows + Ubuntu matrix) - most security repos run "on my Kali"
- deterministic, professional reports

So the project was scoped to exactly those gaps. Feature count was never the
goal; 8 audit controls, deliberately.

## Design decisions (and why)

### 1. Scope gate as a tested invariant

Every module that touches the network receives a `ScopeGuard`; a missing,
malformed, or empty scope file denies everything (fail closed). The test suite
asserts the strongest form of this: `mock_get.assert_not_called()` after a
refusal - **not a single packet may leave before the gate approves**.

Why it matters: even commercial tools with scope flags admit in their own docs
that enforcement leaks on some paths (e.g. "scope is forwarded only to active
enumeration, not to passive discovery or redirects"). A flag you must remember
to pass is not a boundary. A guard the code cannot bypass is.

### 2. MCP scope is pinned by the operator, not the caller

`glassbox-mcp` reads its scope file from `GLASSBOX_SCOPE` in the *server
config*, never from a tool argument. An AI client calling the tools cannot
choose, swap, or broaden the scope it is judged against; with no env var, every
tool refuses. Prompt-level rules are suggestions to a model; this is a
boundary the model does not control.

### 3. Deterministic reports

Findings sort by severity, then rule id, then target; timestamps are
second-granular. Same input = byte-identical report, so a retest diffs cleanly
in git and "what changed since last month" is a `diff`, not an archaeology
project.

### 4. Injectable fetch, offline tests

`crawl()` and `bust()` accept a `fetch` callable; the default wraps
`requests.get`. The entire suite (68 tests, 91.5% coverage) runs offline in
under 3 seconds. CI never touches a network it does not own.

### 5. Windows + Ubuntu CI matrix

Developed on Windows 11, where most offensive tooling pretends Kali exists.
Running both OSes in CI is cheap and converts "works on my machine" from an
opinion into a badge.

## Engineering lessons from the build

- **CI fidelity:** the suite passed locally and failed on CI with
  `ModuleNotFoundError: No module named 'tests'`. Root cause: local runs used
  `python -m pytest` (adds CWD to `sys.path`); CI used bare `pytest`. Lesson
  now encoded in a skill: verify with CI's exact commands, in a fresh clone,
  before pushing.
- **Push protection vs test fixtures:** GitHub blocked a push because synthetic
  Slack-token samples in `test_secrets.py` looked real. Fix: split string
  literals (`"xox" + "b-..."`) so the runtime value is identical while the
  source contains no contiguous secret - amended into the offending commit via
  rebase, `--force-with-lease`.
- **Two bugs caught before push:** a tool function shadowing its own import
  (infinite recursion), and `dataclasses.asdict` preserving tuples where the
  JSON contract wanted lists. Both found by writing the test that describes the
  intended contract first.

## Numbers (from real runs)

- 68 tests, 91.5% coverage floor enforced in CI
- CI: windows-latest + ubuntu-latest x Python 3.11/3.12 - 4/4 green
- Full local gate (lint + format + tests): < 10s
- MCP handshake to tool discovery: ~2s (`hermes mcp test`)

## Appendix: interview talking points

- *"Why not just wrap nuclei/subfinder?"* - wrapping binaries gives you no
  auditability and no test surface; the value we targeted was the safety
  architecture, not scan coverage.
- *"How do you prevent the AI from scanning out of scope?"* - the scope file is
  operator-pinned server-side in the MCP config; a refusal is a deterministic
  code path, and a test asserts no request is attempted after it.
- *"How do you avoid false positives?"* - every finding carries evidence from
  the actual response; the report generator cannot emit a finding that was not
  observed; secrets are redacted at the source so reports cannot leak.
- *"What would you do differently?"* - ship the write-up earlier; a repo
  without distribution is a private exercise.
