# Scope & Authorization Policy

This document is part of the product, not a disclaimer added late.

## The rule

Glassbox Recon only talks to hosts you have **written authorization** to test:
your own systems, a local lab, or a bug-bounty target within the published
scope. The operator proves this by putting the target in the engagement scope
file - the code's only other answer is "no".

## How enforcement works

1. Every command requires `--scope <file>`. There is no bypass flag, no
   environment variable that disables it, no "just this once" option.
2. `ScopeGuard` is plain deterministic Python - no model in the decision path,
   so the same input always yields the same verdict.
3. **Fail closed.** Missing file, unreadable file, malformed JSON, empty
   `allow` list: all deny everything. A broken scope file stops the run; it
   never silently widens it.
4. `deny` always wins over `allow`, and `*.example.com` covers subdomains but
   never the bare apex domain.
5. Every refusal prints the host and the reason, and exits with code 2.
6. In MCP mode the scope file comes from the operator's `GLASSBOX_SCOPE`
   environment variable in the client config - never from a tool argument, so
   an AI client cannot choose, swap, or broaden the scope it is judged against.

## Refusal list (features that will not be added)

- Exploitation payloads or vulnerability verification (use a dedicated,
  authorized tool under a real engagement process).
- DoS, flooding, rate-limit exhaustion - of any target, including your own.
- Authentication attacks: spraying, stuffing, brute force.
- WAF/evasion modules and payload obfuscation.
- Automatic scope discovery ("scan whatever looks like the target").

These are rejections, not roadmap items.

## Operator responsibilities

- Rate limit: honor `rate_limit_rps` from the scope file; the bundled example
  runs at 5 req/s.
- Non-destructive by default: only GET/HEAD are issued unless
  `allow_mutations` is explicitly true in the scope file.
- The bundled lab app (`lab/mock_app.py`) binds to 127.0.0.1 only. Do not
  expose it, and do not point this tool at someone else's system to "see what
  it finds".

## Report integrity

Findings record observed facts with evidence. The tool never reports a
vulnerability class it did not see in a response, and secrets in its own
output are redacted by design so a report cannot leak what it found.
