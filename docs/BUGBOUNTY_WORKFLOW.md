# Bug Bounty Workflow

How to use Glassbox Recon inside a real bug-bounty engagement - honestly, with
expectations set before the first request.

## 1. Map the program scope into a scope file (before anything else)

Take the program's published scope page and encode it literally:

```json
{
  "engagement": "hackerone-<program>",
  "authorized_by": "program policy (published scope)",
  "allow": ["*.target-example.com", "target-example.com"],
  "deny": ["admin.target-example.com", "status.target-example.com"],
  "rate_limit_rps": 2,
  "allow_mutations": false
}
```

Rules that matter:

- `deny` = the program's *out-of-scope* list. Exclusions always win.
- Rate: use the program's stated limit; when in doubt go slower (2 rps here as
  a conservative default).
- One scope file per program, named after it. Never reuse a permissive file.

## 2. What this tool actually covers

| Tool | Maps to | Realistic outcome on mature programs |
|---|---|---|
| `probe` | Security misconfiguration (headers, cookies, CORS) | Usually informative / best-practice |
| `bust` | Exposed files/directories (`.env`, backups, `.git`) | **Can be valid medium/high if something real is exposed** |
| `secrets` | Leaked credentials in accessible files | **Valid when a real secret is confirmed (redacted evidence included)** |
| `crawl` | Attack-surface mapping for follow-up manual testing | Not a finding by itself; input for you |

Honest expectation: a missing CSP header alone is triaged NA/informative on
most mature programs. The findings that *pay* are the ones this pipeline can
occasionally surface underneath the headers: an exposed `.env` via `bust`, a
committed token via `secrets`, CORS `*` + credentials via `probe` (that one is
a real, reportable misconfiguration - the tool flags it as HIGH for a reason).

## 3. Per-engagement flow

```text
1. scope file per program           (section 1)
2. validate_scope <asset>           confirm in-scope before testing
3. probe / bust / crawl / secrets   rate-limited, GET-only, non-destructive
4. verify manually                  reproduce each finding by hand - the tool
                                    raises hypotheses, you confirm them
5. report                           templates/report_template.md -> PDF
6. log the submission               findings + evidence + remediation
```

Step 4 is not optional: automated findings are leads, not verdicts. A triager
will ask for reproduction steps; provide the raw request/response from your own
verification, not the tool's summary.

## 4. Hard lines (same as the repo's policy)

- Only targets the program lists, only while the program is live.
- No DoS, no flooding, no authentication attacks, no exploitation of
  business logic beyond the program's rules.
- If a redirect or response takes you to a host outside `allow` - stop, do not
  follow. (The crawler records off-site links instead of following them for
  exactly this reason.)

## 5. Build the habit locally first

Practice the full loop against deliberately vulnerable local apps (OWASP Juice
Shop, DVWA - Docker one-liners) with `scope.json` pointing only at
`127.0.0.1`. The workflow, the report, the verification discipline - rehearse
all of it where the only possible victim is your own machine.
