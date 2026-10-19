"""Crawler tests with an injected fetch function - no network, ever."""

from __future__ import annotations

import pytest

from glassbox.crawler import crawl
from glassbox.scope import ScopeViolation

HOME = """<html><body>
  <a href="/about">About</a>
  <a href="/search?q=test&page=2">Search</a>
  <a href="https://external.example.com/away">External</a>
  <form action="/login" method="post">
    <input name="username"><input name="password" type="password">
  </form>
  <a href="#section">Fragment only</a>
  <a href="mailto:x@example.com">Mail</a>
</body></html>"""

ABOUT = '<html><body><a href="/team">Team</a></body></html>'
TEAM = "<html><body><p>team page, no links</p></body></html>"
SEARCH = "<html><body><p>results</p></body></html>"
LOGIN = "<html><body><p>form target</p></body></html>"


def fake_fetch(pages: dict[str, str]):
    """Return a fetch function serving a fixed URL -> HTML map."""

    def _fetch(url: str) -> str:
        key = url.split("?")[0].rstrip("/")
        for known, html in pages.items():
            if key == known.rstrip("/"):
                return html
        raise AssertionError(f"unexpected fetch: {url}")

    return _fetch


def test_crawl_collects_endpoints_and_params(guard) -> None:
    pages = {
        "http://127.0.0.1:8888": HOME,
        "http://127.0.0.1:8888/about": ABOUT,
        "http://127.0.0.1:8888/team": TEAM,
        "http://127.0.0.1:8888/search": SEARCH,
        "http://127.0.0.1:8888/login": LOGIN,
    }
    result = crawl("http://127.0.0.1:8888/", guard, fetch=fake_fetch(pages))

    assert "http://127.0.0.1:8888/about" in result.endpoints
    assert "http://127.0.0.1:8888/login" in result.endpoints  # form action discovered
    assert "http://127.0.0.1:8888/team" in result.endpoints  # reached at depth 2
    assert any("external.example.com" in u for u in result.skipped_offsite)
    assert result.errors == []


def test_parameters_from_query_and_forms(guard) -> None:
    pages = {
        "http://127.0.0.1:8888": HOME,
        "http://127.0.0.1:8888/search": SEARCH,
        "http://127.0.0.1:8888/login": LOGIN,
        "http://127.0.0.1:8888/about": ABOUT,
        "http://127.0.0.1:8888/team": TEAM,
    }
    result = crawl("http://127.0.0.1:8888/", guard, fetch=fake_fetch(pages))

    search_params = result.parameters.get("http://127.0.0.1:8888/search", [])
    assert "q" in search_params and "page" in search_params
    login_params = result.parameters.get("http://127.0.0.1:8888/login", [])
    assert "username" in login_params and "password" in login_params


def test_max_depth_limits_frontier(guard) -> None:
    pages = {
        "http://127.0.0.1:8888": HOME,
        "http://127.0.0.1:8888/about": ABOUT,
        "http://127.0.0.1:8888/search": SEARCH,
        "http://127.0.0.1:8888/login": LOGIN,
    }
    # depth 0 only: the seed is visited, its links are collected but not followed
    result = crawl("http://127.0.0.1:8888/", guard, max_depth=0, fetch=fake_fetch(pages))
    assert result.visited == ["http://127.0.0.1:8888/"]
    assert "http://127.0.0.1:8888/about" in result.endpoints  # still recorded


def test_max_pages_stops_the_walk(guard) -> None:
    pages = {
        "http://127.0.0.1:8888": HOME,
        "http://127.0.0.1:8888/about": ABOUT,
        "http://127.0.0.1:8888/search": SEARCH,
        "http://127.0.0.1:8888/login": LOGIN,
        "http://127.0.0.1:8888/team": TEAM,
    }
    result = crawl("http://127.0.0.1:8888/", guard, max_pages=2, fetch=fake_fetch(pages))
    assert len(result.visited) <= 2


def test_scope_violation_blocks_crawl(guard) -> None:
    with pytest.raises(ScopeViolation):
        crawl("https://example.com/", guard, fetch=lambda url: "<html></html>")


def test_fetch_error_is_recorded_not_fatal(guard) -> None:
    import requests as req

    def broken_fetch(url: str) -> str:
        raise req.RequestException("connection refused")

    result = crawl("http://127.0.0.1:8888/", guard, fetch=broken_fetch)
    assert result.errors and "connection refused" in result.errors[0]
