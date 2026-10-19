"""Regex-based credential scanner.

Rules live in one declarative table so a reviewer can audit every pattern at a
glance. Matching secrets are REDACTED in findings (first 4 + last 4 characters
only) - the tool's own reports must never become a credential leak.

No entropy-based detection on purpose: every rule here is explainable and
testable with a synthetic sample. Entropy scoring is listed as future work in
the roadmap rather than smuggled in as unverifiable cleverness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .probe import Finding


@dataclass(frozen=True)
class SecretRule:
    """One credential pattern: id, human description, severity, regex, fix hint."""

    rule_id: str
    description: str
    severity: str
    pattern: re.Pattern[str]
    remediation: str


def _rule(
    rule_id: str, description: str, severity: str, regex: str, remediation: str
) -> SecretRule:
    return SecretRule(
        rule_id=rule_id,
        description=description,
        severity=severity,
        pattern=re.compile(regex),
        remediation=remediation,
    )


RULES: tuple[SecretRule, ...] = (
    _rule(
        "secret.aws.access_key_id",
        "AWS Access Key ID",
        "high",
        r"\bAKIA[0-9A-Z]{16}\b",
        "Rotate the key in IAM and scope its permissions down.",
    ),
    _rule(
        "secret.aws.secret_access_key",
        "AWS-like secret access key assignment",
        "high",
        r"(?i)aws.{0,20}secret.{0,20}[=:'\"\s][\"']?([A-Za-z0-9/+=]{40})[\"']?",
        "Rotate the key; load it from the environment, never from source.",
    ),
    _rule(
        "secret.github.pat",
        "GitHub personal access token",
        "high",
        r"\bghp_[A-Za-z0-9]{36}\b",
        "Revoke the token in GitHub settings and reissue with minimal scopes.",
    ),
    _rule(
        "secret.github.oauth",
        "GitHub OAuth token",
        "high",
        r"\bgho_[A-Za-z0-9]{36}\b",
        "Revoke the OAuth app token in GitHub settings.",
    ),
    _rule(
        "secret.slack.token",
        "Slack API token",
        "high",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
        "Revoke the token in the Slack app admin panel.",
    ),
    _rule(
        "secret.slack.webhook",
        "Slack webhook URL (contains an incoming webhook secret)",
        "medium",
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+",
        "Rotate the webhook; treat the URL as a password.",
    ),
    _rule(
        "secret.stripe.live_key",
        "Stripe live secret key",
        "high",
        r"\bsk_live_[0-9a-zA-Z]{24,}\b",
        "Roll the key in the Stripe dashboard immediately.",
    ),
    _rule(
        "secret.google.api_key",
        "Google API key",
        "medium",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        "Restrict the key by API and IP referrer in Google Cloud console.",
    ),
    _rule(
        "secret.sendgrid.api_key",
        "SendGrid API key",
        "high",
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        "Rotate the SendGrid API key.",
    ),
    _rule(
        "secret.npm.token",
        "npm access token",
        "high",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        "Revoke the npm token in your access-token settings.",
    ),
    _rule(
        "secret.pgp.block",
        "PGP/GPG private key block",
        "high",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "The private key is committed; pull it from history and rotate the keypair.",
    ),
    _rule(
        "secret.pem.private_key",
        "PEM-encoded private key block",
        "high",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "The private key is committed; pull it from history and rotate the keypair.",
    ),
    _rule(
        "secret.jwt",
        "JSON Web Token",
        "medium",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "Tokens in source leak session access; rotate and move to runtime secrets.",
    ),
    _rule(
        "secret.url.basic_auth",
        "Credential embedded in URL (user:password@host)",
        "high",
        r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@",
        "Never embed credentials in URLs; use headers or a secret store.",
    ),
    _rule(
        "secret.password.assignment",
        "Hardcoded password assignment",
        "medium",
        r"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
        "Move the value to an environment variable or secret manager.",
    ),
    _rule(
        "secret.api_key.assignment",
        "Hardcoded API key assignment",
        "medium",
        r"(?i)\bapi[_-]?key\s*[=:]\s*['\"][A-Za-z0-9_-]{16,}['\"]",
        "Move the value to an environment variable or secret manager.",
    ),
    _rule(
        "secret.database.url",
        "Database connection string with embedded credentials",
        "high",
        r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]+:[^/\s:@]+@",
        "Connection strings with passwords belong in the environment, not in code.",
    ),
)


def _redact(value: str) -> str:
    """Reduce a match to first 4 + last 4 characters so reports never leak it."""
    if len(value) <= 12:
        return value[:2] + "..." + value[-2:]
    return f"{value[:4]}...{value[-4:]}"


def scan_text(text: str, target: str = "<text>") -> list[Finding]:
    """Run every rule over `text`; return one Finding per unique match."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            evidence = _redact(match.group(0).strip())
            dedupe_key = (rule.rule_id, evidence)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    target=target,
                    description=f"Possible {rule.description} found.",
                    evidence=evidence,
                    remediation=rule.remediation,
                )
            )
    return findings


def scan_file(path: Path) -> list[Finding]:
    """Scan a file on disk. Binary files are reported as skipped, not guessed at."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [
            Finding(
                rule_id="secret.scan.skipped_binary",
                severity="info",
                target=str(file_path),
                description="File is not UTF-8 text; skipped instead of guessing at bytes.",
                evidence="UnicodeDecodeError on utf-8 read",
                remediation="Inspect binaries manually if they may embed credentials.",
            )
        ]
    return scan_text(text, target=str(file_path))
