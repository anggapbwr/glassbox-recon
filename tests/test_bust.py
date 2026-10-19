"""Content discovery tests with an injected fetch - classification, not speed."""

from __future__ import annotations

from glassbox.bust import bust, load_wordlist


def test_hits_classified_and_sorted(guard) -> None:
    responses = {
        "http://127.0.0.1:8888/admin": (403, 120),
        "http://127.0.0.1:8888/login": (200, 4096),
        "http://127.0.0.1:8888/nope": (404, 30),
        "http://127.0.0.1:8888/secret": (401, 88),
    }

    def fetch(url: str) -> tuple[int, int]:
        return responses.get(url, (404, 30))

    results = bust(
        "http://127.0.0.1:8888/", guard, wordlist=["admin", "login", "nope", "secret"], fetch=fetch
    )
    urls = [d.url for d in results]
    assert urls == sorted(urls)
    assert "http://127.0.0.1:8888/nope" not in urls  # 404 filtered out

    by_url = {d.url: d for d in results}
    assert by_url["http://127.0.0.1:8888/admin"].note == "exists but access is forbidden"
    assert by_url["http://127.0.0.1:8888/secret"].note == "exists but requires authentication"


def test_network_error_treated_as_miss(guard) -> None:
    import requests as req

    def fetch(url: str) -> tuple[int, int]:
        if url.endswith("/admin"):
            return 200, 10
        raise req.RequestException("reset by peer")

    results = bust("http://127.0.0.1:8888/", guard, wordlist=["admin", "broken"], fetch=fetch)
    assert [d.url for d in results] == ["http://127.0.0.1:8888/admin"]


def test_bundled_wordlist_loads() -> None:
    words = load_wordlist()
    assert len(words) >= 150
    assert "admin" in words and ".env" in words
    assert all(w == w.strip() and w for w in words)  # no blank/whitespace rows
