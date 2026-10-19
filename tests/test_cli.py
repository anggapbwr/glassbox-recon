"""CLI tests: exit codes, refusal paths, and output shapes - all offline."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import glassbox.probe as probe_mod
from glassbox.cli import main


def _resp(
    headers: dict[str, str], status: int = 200, url: str = "http://127.0.0.1:8888/"
) -> MagicMock:
    resp = MagicMock()
    resp.headers = headers
    resp.status_code = status
    resp.url = url
    return resp


def test_version_flag(capsys) -> None:
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "glassbox" in capsys.readouterr().out


def test_missing_scope_flag_is_usage_error(tmp_path: Path) -> None:
    try:
        main(["probe", "http://127.0.0.1:8888/"])
    except SystemExit as exc:
        assert exc.code == 2  # argparse refuses: there is no bypass flag


def test_probe_out_of_scope_exits_2(scope_file: Path, capsys) -> None:
    code = main(["probe", "https://example.com/", "--scope", str(scope_file)])
    assert code == 2
    assert "refused:" in capsys.readouterr().err


def test_probe_missing_scope_file_exits_2(tmp_path: Path, capsys) -> None:
    code = main(["probe", "http://127.0.0.1:8888/", "--scope", str(tmp_path / "nope.json")])
    assert code == 2
    assert "Failing closed" in capsys.readouterr().err


def test_probe_markdown_output(scope_file: Path, capsys) -> None:
    headers = {"Server": "nginx"}
    with patch.object(probe_mod.requests, "get", return_value=_resp(headers)):
        code = main(["probe", "http://127.0.0.1:8888/", "--scope", str(scope_file)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Glassbox report" in out
    assert "header.csp.missing" in out
    assert "probed http://127.0.0.1:8888/ -> 200" in out


def test_probe_json_output(scope_file: Path, capsys) -> None:
    with patch.object(probe_mod.requests, "get", return_value=_resp({})):
        code = main(["probe", "http://127.0.0.1:8888/", "--scope", str(scope_file), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["target"] == "http://127.0.0.1:8888/"
    assert payload["findings"]


def test_secrets_command(scope_file: Path, tmp_path: Path, capsys) -> None:
    target = tmp_path / "app.py"
    target.write_text('KEY = "ghp_' + "a" * 36 + '"', encoding="utf-8")
    code = main(["secrets", str(target), "--scope", str(scope_file), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["findings"][0]["rule_id"] == "secret.github.pat"
    assert "a" * 36 not in payload["findings"][0]["evidence"]  # redacted


def test_crawl_command_json(scope_file: Path, capsys) -> None:
    html = '<html><body><a href="/about">x</a></body></html>'

    with patch.object(probe_mod.requests, "get", return_value=_resp({})) as mock_get:
        mock_get.return_value.text = html
        with patch("glassbox.crawler.requests.get", return_value=MagicMock(text=html)):
            code = main(["crawl", "http://127.0.0.1:8888/", "--scope", str(scope_file), "--json"])
    out = capsys.readouterr().out
    assert code == 0
    assert '"endpoints"' in out


def test_bust_command_reports_hits(scope_file: Path, capsys) -> None:
    def fake_fetch(url: str) -> tuple[int, int]:
        return (200, 42) if url.endswith("/admin") else (404, 30)

    with patch(
        "glassbox.bust.requests.get",
        side_effect=lambda url, **kw: MagicMock(
            status_code=fake_fetch(url)[0], content=b"x" * fake_fetch(url)[1]
        ),
    ):
        code = main(["bust", "http://127.0.0.1:8888/", "--scope", str(scope_file)])
    out = capsys.readouterr().out
    assert code == 0
    assert "hit(s)" in out
    assert "/admin" in out
