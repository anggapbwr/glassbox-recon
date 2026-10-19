# Security Assessment Report Template

Professional engagement-report skeleton for glassbox-recon findings (or any
manual findings you add by hand). Fill `{{TOKENS}}`, delete guidance comments
(`<!-- ... -->`), then render to PDF:

    pandoc report.md -o report.pdf --toc --number-sections

Mapping from tool output: run `glassbox probe <url> --scope <file> --json` and
place each `findings[]` entry into section 6 (rule_id -> title, description ->
Observation, evidence -> Evidence, remediation -> Remediation). Tool-generated
Markdown (`glassbox probe <url> --scope <file>`) already follows sections 1-6.

---

<!-- ========================= COVER ========================= -->

# {{ORG_NAME}}

# Security Assessment Report

**{{ENGAGEMENT_TITLE}}**

| Document control | |
|---|---|
| Report ID | {{ENGAGEMENT_ID}} |
| Version | {{v1.0}} |
| Classification | CONFIDENTIAL |
| Date issued | {{YYYY-MM-DD}} |
| Prepared for | {{CLIENT_NAME}} |
| Prepared by | {{ASSESSOR_NAME / ORG}} |
| Technical reviewer | {{REVIEWER_NAME}} |
| Engagement window | {{start}} - {{end}} |

> **Confidentiality notice:** this report contains security information about
> {{CLIENT_NAME}}. Distribution is limited to the named recipients.

<!-- =================== 1. EXECUTIVE SUMMARY =================== -->

## 1. Executive Summary

{{One paragraph: business context, what was assessed, why.}}

{{One paragraph: what was found, in plain language - no rule IDs here.}}

Overall risk posture: **{{HIGH | MODERATE | LOW | INFORMATIONAL}}**.

| Severity | Count |
|---|---|
| High | {{n}} |
| Medium | {{n}} |
| Low | {{n}} |
| Info | {{n}} |

Key recommendations (top 3, one line each):

1. {{recommendation}}
2. {{recommendation}}
3. {{recommendation}}

<!-- ================ 2. SCOPE & OBJECTIVES ================ -->

## 2. Scope & Objectives

**Objectives:** {{what the assessment set out to answer}}

| In scope | Out of scope |
|---|---|
| {{hosts / apps / URLs}} | {{production data, DoS, social engineering, ...}} |

Rules of engagement: non-destructive testing only; GET/HEAD unless agreed
otherwise; rate limits per agreement; emergency contact {{CONTACT}}.

## 3. Methodology

- {{Automated: glassbox-recon {{VERSION}} - header/cookie/CORS audit, TLS
  inspection, content discovery, credential scan (redacted evidence).}}
- {{Manual: {{list checks not covered by the tool}}}}
- Severity scale: **High** fix as priority / **Medium** should fix / **Low**
  hardening / **Info** hygiene observation.

<!-- ================= 4. RISK DEFINITIONS ================= -->

## 4. Risk Rating Definitions

| Severity | Definition | Target fix window |
|---|---|---|
| High | Directly exploitable or exposes sensitive data | 7 days |
| Medium | Weakens defense in depth; exploitable in combination | 30 days |
| Low | Hardening gap with limited direct impact | 90 days |
| Info | Observation worth tracking; no direct risk | Next cycle |

<!-- =============== 5. FINDINGS SUMMARY MATRIX =============== -->

## 5. Findings Summary

| ID | Severity | Finding | Location | Status |
|---|---|---|---|---|
| F-001 | {{HIGH}} | {{short title}} | {{url / endpoint / file}} | {{Open}} |
| F-002 | {{MEDIUM}} | {{short title}} | {{location}} | {{Open}} |

## 6. Detailed Findings

<!-- One block per finding. Delete this guidance and repeat the block. -->

### F-001 [{{HIGH}}] {{Finding title}}

- **Severity**: {{HIGH}}
- **CWE / reference**: {{CWE-XXX / OWASP {{category}} / {{rule_id}}}}
- **Location**: {{exact URL, parameter, header, or file path}}
- **Observation**: {{what was observed, factual, no speculation}}
- **Evidence**: {{raw response excerpt / redacted token / screenshot caption -
  evidence must be reproducible}}
- **Impact**: {{what an attacker gains - business language}}
- **Remediation**: {{concrete fix; config snippet or header value if possible}}
- **Validation**: {{how to verify the fix, one step}}

## 7. Positive Observations

{{Controls that worked well - professional reports are balanced.}}

- {{e.g. security headers present and correctly configured on main app}}

## 8. Remediation Roadmap

| ID | Priority | Effort | Owner | Target date |
|---|---|---|---|---|
| F-001 | {{P1}} | {{S}} | {{team}} | {{date}} |
| F-002 | {{P2}} | {{M}} | {{team}} | {{date}} |

## 9. Appendices

- **A - Tools & checks executed**: {{tool versions, check list}}
- **B - Evidence index**: {{paths to raw logs / recon/ directory}}
- **C - Glossary**: {{terms for non-technical readers}}

---

**Sign-off**

Prepared by: {{name, role, date}} &#160;&#160; Reviewed by: {{name, role, date}}

_Client acceptance: {{name, signature, date}}_
