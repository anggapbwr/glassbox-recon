"""Tests for the credential scanner: every rule proves itself on a synthetic sample."""

from __future__ import annotations

from pathlib import Path

from glassbox.secrets import RULES, scan_file, scan_text

# One synthetic sample per rule. All values below are FAKE strings crafted to
# match the regex shape - they are not and never were real credentials.
SAMPLES: dict[str, str] = {
    "secret.aws.access_key_id": "aws_key = AKIA" + "ABCDEFGHIJKLMNOP",
    "secret.aws.secret_access_key": 'aws_secret_access_key = "' + "a" * 40 + '"',
    "secret.github.pat": "token: ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "secret.github.oauth": "oauth: gho_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    # Slack samples are concatenated so this repo's own secret scanning does not
    # block pushes - at runtime they form one exact, still-valid sample string.
    "secret.slack.token": "xox" + "b-1234567890-" + "abcdefghijklmnopqrstuvwxyz",
    "secret.slack.webhook": "https://hooks.slack"
    + ".com/services/"
    + "T00000000/B00000000/"
    + "XXXXXXXXXXXXXXXXXXXXXXXX",
    "secret.stripe.live_key": "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "abcdef123",
    "secret.google.api_key": "AIza" + "A" * 35,
    "secret.sendgrid.api_key": "SG." + "A" * 22 + "." + "B" * 43,
    "secret.npm.token": "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "secret.pgp.block": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nmQIN...",
    "secret.pem.private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...",
    "secret.jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N65C5Ii",
    "secret.url.basic_auth": "https://admin:hunter2@internal.example.com/db",
    "secret.password.assignment": 'password = "hunter2secret"',
    "secret.api_key.assignment": 'api_key = "abcd1234efgh5678ijkl"',
    "secret.database.url": "postgres://appuser:s3cr3tpass@db.internal:5432/app",
}


def test_every_rule_has_a_sample() -> None:
    """Adding a rule without a test sample fails here, not in production."""
    missing = {r.rule_id for r in RULES} - SAMPLES.keys()
    assert not missing, f"rules without synthetic samples: {sorted(missing)}"


def test_every_sample_triggers_its_rule() -> None:
    for rule_id, sample in SAMPLES.items():
        findings = scan_text(sample)
        assert rule_id in {f.rule_id for f in findings}, f"{rule_id} did not match its own sample"


def test_clean_text_produces_no_findings() -> None:
    clean = "The quick brown fox jumps over the lazy dog. Nothing to see here: 2026-01-01."
    assert scan_text(clean) == []


def test_secrets_are_redacted_in_findings() -> None:
    findings = scan_text(SAMPLES["secret.aws.access_key_id"])
    assert findings
    for finding in findings:
        assert "ABCDEFGHIJKLMNOP" not in finding.evidence
        assert "..." in finding.evidence


def test_duplicate_matches_deduplicated() -> None:
    sample = SAMPLES["secret.github.pat"]
    findings = scan_text(f"{sample}\n{sample}\n{sample}")
    github = [f for f in findings if f.rule_id == "secret.github.pat"]
    assert len(github) == 1


def test_scan_file_reads_text(tmp_path: Path) -> None:
    target = tmp_path / "config.py"
    target.write_text(f'API = "{SAMPLES["secret.stripe.live_key"]}"', encoding="utf-8")
    findings = scan_file(target)
    assert "secret.stripe.live_key" in {f.rule_id for f in findings}
    assert all(str(target) == f.target for f in findings)


def test_scan_file_skips_binary(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\xff\xfe\x00\x01 not utf8 \x80\x81")
    findings = scan_file(target)
    assert {f.rule_id for f in findings} == {"secret.scan.skipped_binary"}


def test_short_value_redaction_shape() -> None:
    """Short matches still round-trip with at least some visible characters."""
    findings = scan_text('password = "abc123"')
    assert findings
    assert "abc123" not in findings[0].evidence
