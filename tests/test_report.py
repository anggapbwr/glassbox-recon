"""Report tests: deterministic ordering, professional structure, clean empties."""

from __future__ import annotations

import json

from glassbox.probe import Finding
from glassbox.report import sort_findings, to_json, to_markdown


def f(rule_id: str, severity: str, target: str = "http://t/") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        target=target,
        description="observed thing",
        evidence="the actual evidence",
        remediation="the actual fix",
    )


def test_severity_ordering_high_first() -> None:
    findings = [
        f("a.info", "info"),
        f("b.high", "high"),
        f("c.low", "low"),
        f("d.medium", "medium"),
    ]
    ordered = [x.severity for x in sort_findings(findings)]
    assert ordered == ["high", "medium", "low", "info"]


def test_tie_broken_by_rule_id_then_target() -> None:
    findings = [
        f("z.rule", "low", "http://b/"),
        f("a.rule", "low", "http://z/"),
        f("z.rule", "low", "http://a/"),
    ]
    ordered = [(x.rule_id, x.target) for x in sort_findings(findings)]
    assert ordered == [("a.rule", "http://z/"), ("z.rule", "http://a/"), ("z.rule", "http://b/")]


def test_report_has_professional_structure() -> None:
    md = to_markdown([f("x.high", "high"), f("y.info", "info")], "http://target/", "lab-eng")
    assert md.startswith("# Security Assessment Report")
    # cover block
    assert "| Engagement | lab-eng |" in md
    assert "| Target | http://target/ |" in md
    assert "CONFIDENTIAL" in md
    # executive summary + posture + counts table
    assert "## 1. Executive Summary" in md
    assert "Overall risk posture: **HIGH**" in md
    assert "| High | 1 |" in md
    assert "| Info | 1 |" in md
    # findings matrix + detail ids
    assert "| F-001 | HIGH | x.high |" in md
    assert "### F-001 [HIGH] x.high" in md
    # evidence and remediation present verbatim
    assert "the actual evidence" in md
    assert "the actual fix" in md
    # closing sections
    assert "## 4. Methodology" in md
    assert "## 5. Scope & Limitations" in md
    assert "## 6. Disclaimer" in md


def test_matrix_and_ids_follow_sorted_order() -> None:
    md = to_markdown([f("b.rule", "medium"), f("a.rule", "medium")], "http://t/")
    first = md.index("| F-001 | MEDIUM | a.rule |")
    second = md.index("| F-002 | MEDIUM | b.rule |")
    assert first < second


def test_empty_findings_still_professional() -> None:
    md = to_markdown([], "http://target/", "clean-eng")
    assert "No findings were confirmed against the checked controls." in md
    assert "Overall risk posture: **INFORMATIONAL**" in md
    assert "| High | 0 |" in md
    assert "_None._" in md
    assert "No findings to detail." in md
    assert "## 6. Disclaimer" in md


def test_json_round_trips_counts_and_provenance() -> None:
    payload = json.loads(
        to_json([f("x.high", "high"), f("y.high", "high")], "http://target/", "eng")
    )
    assert payload["target"] == "http://target/"
    assert payload["engagement"] == "eng"
    assert payload["counts"] == {"high": 2}
    assert payload["posture"] == "HIGH"
    assert payload["tool_version"]
    assert len(payload["findings"]) == 2
    assert payload["findings"][0]["rule_id"] == "x.high"
    assert set(payload["findings"][0]) == {
        "rule_id",
        "severity",
        "target",
        "description",
        "evidence",
        "remediation",
    }


def test_reports_are_deterministic() -> None:
    findings = [f("b.rule", "medium"), f("a.rule", "medium")]
    assert to_markdown(findings, "t") == to_markdown(list(reversed(findings)), "t")
