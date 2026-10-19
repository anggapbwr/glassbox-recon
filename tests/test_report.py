"""Report tests: deterministic ordering and well-formed renders."""

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


def test_markdown_contains_header_counts_and_evidence() -> None:
    md = to_markdown([f("x.high", "high"), f("y.info", "info")], "http://target/", "lab-eng")
    assert "# Glassbox report - http://target/" in md
    assert "Engagement: lab-eng" in md
    assert "high: 1" in md and "info: 1" in md
    assert "[HIGH] x.high" in md
    assert "the actual evidence" in md


def test_markdown_empty_findings_handled() -> None:
    md = to_markdown([], "http://target/")
    assert "No findings" in md


def test_json_round_trips_and_counts() -> None:
    payload = json.loads(
        to_json([f("x.high", "high"), f("y.high", "high")], "http://target/", "eng")
    )
    assert payload["target"] == "http://target/"
    assert payload["engagement"] == "eng"
    assert payload["counts"] == {"high": 2}
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
