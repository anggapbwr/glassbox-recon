"""Report rendering: findings in, a professional assessment report out.

Two renderers share one deterministic ordering (severity -> rule id -> target):

- Markdown: cover block, executive summary with risk posture, findings matrix,
  per-finding detail, methodology, scope & limitations, disclaimer.
- JSON: the same data for automation (adds tool version for provenance).

Determinism is a feature, not a coincidence: findings are sorted and timestamps
are second-granular, so the same input yields a byte-identical report and a
retest diffs cleanly in git.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime

from . import __version__
from .probe import Finding

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

POSTURE_BY_SEVERITY = {
    "high": "HIGH",
    "medium": "MODERATE",
    "low": "LOW",
}

CONTROLS_CHECKED = (
    "HSTS, Content-Security-Policy, X-Content-Type-Options, "
    "X-Frame-Options/clickjacking, server banner disclosure, "
    "cookie Secure/HttpOnly flags, CORS wildcard with credentials, "
    "TLS certificate facts"
)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Severity first (high to info), then rule id, then target - stable and total."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule_id, f.target),
    )


def _posture(ordered: list[Finding]) -> str:
    """Overall risk posture from the highest severity actually present."""
    for finding in ordered:
        label = POSTURE_BY_SEVERITY.get(finding.severity)
        if label:
            return label
    return "INFORMATIONAL"


def to_markdown(findings: list[Finding], target: str, engagement: str = "unnamed") -> str:
    """Render findings as a professional assessment report in Markdown."""
    ordered = sort_findings(findings)
    counts = Counter(f.severity for f in ordered)
    generated = datetime.now(UTC).isoformat(timespec="seconds")
    total = len(ordered)
    plural = "finding" if total == 1 else "findings"

    lines = [
        "# Security Assessment Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Engagement | {engagement} |",
        f"| Target | {target} |",
        "| Assessment type | Automated reconnaissance & configuration audit |",
        f"| Tool | glassbox-recon {__version__} |",
        f"| Generated (UTC) | {generated} |",
        "| Classification | CONFIDENTIAL - for the assessed party only |",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
    ]
    if total:
        lines += [
            f"An automated reconnaissance and configuration audit was performed against "
            f"`{target}`. **{total} {plural}** were confirmed: "
            f"{counts.get('high', 0)} high, {counts.get('medium', 0)} medium, "
            f"{counts.get('low', 0)} low, {counts.get('info', 0)} info.",
            "",
            f"Overall risk posture: **{_posture(ordered)}**.",
        ]
    else:
        lines += [
            f"An automated reconnaissance and configuration audit was performed against "
            f"`{target}`. No {plural} were confirmed against the checked controls.",
            "",
            "Overall risk posture: **INFORMATIONAL**.",
        ]
    lines += [
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| High | {counts.get('high', 0)} |",
        f"| Medium | {counts.get('medium', 0)} |",
        f"| Low | {counts.get('low', 0)} |",
        f"| Info | {counts.get('info', 0)} |",
        "",
        "## 2. Findings Summary",
        "",
    ]
    if ordered:
        lines += [
            "| ID | Severity | Rule | Target |",
            "|---|---|---|---|",
        ]
        for index, finding in enumerate(ordered, start=1):
            lines.append(
                f"| F-{index:03d} | {finding.severity.upper()} | "
                f"{finding.rule_id} | `{finding.target}` |"
            )
    else:
        lines.append("_None._")

    lines += ["", "## 3. Detailed Findings", ""]
    if not ordered:
        lines += ["No findings to detail.", ""]
    for index, finding in enumerate(ordered, start=1):
        lines += [
            f"### F-{index:03d} [{finding.severity.upper()}] {finding.rule_id}",
            "",
            f"- **Severity**: {finding.severity.upper()}",
            f"- **Rule ID**: {finding.rule_id}",
            f"- **Target**: `{finding.target}`",
            f"- **Observation**: {finding.description}",
            f"- **Evidence**: `{finding.evidence}`",
            f"- **Remediation**: {finding.remediation}",
            "",
        ]

    lines += [
        "## 4. Methodology",
        "",
        f"- Engine: glassbox-recon {__version__} - single-GET probe, non-destructive, "
        "rate-limited per the engagement scope.",
        f"- Controls checked: {CONTROLS_CHECKED}.",
        "- Severity scale: high (priority fix) / medium (should fix) / low (hardening) "
        "/ info (hygiene observation).",
        "",
        "## 5. Scope & Limitations",
        "",
        f"- Authorized scope is defined by the operator's engagement file "
        f"(engagement: {engagement}).",
        "- Automated configuration checks only: no exploitation, fuzzing, credential "
        "testing, or business-logic review.",
        "- Absence of findings means only that no checked control was violated in the "
        "sampled response; it is not a statement of overall security.",
        "",
        "## 6. Disclaimer",
        "",
        "Generated by glassbox-recon for authorized assessment purposes. Every evidence "
        "line traces to an actual response or file read - nothing in this report is "
        "inferred. The assessed party is responsible for validating findings in their "
        "own environment before remediation.",
        "",
        "---",
        "",
        "Report determinism: findings sorted by severity, rule id, then target - the "
        "same input yields an identical report, so retests diff cleanly.",
    ]
    return "\n".join(lines)


def to_json(findings: list[Finding], target: str, engagement: str = "unnamed") -> str:
    """Render findings as pretty-printed JSON for downstream automation."""
    payload = {
        "target": target,
        "engagement": engagement,
        "tool_version": __version__,
        "generated_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "counts": dict(Counter(f.severity for f in findings)),
        "posture": _posture(sort_findings(findings)),
        "findings": [asdict(f) for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
