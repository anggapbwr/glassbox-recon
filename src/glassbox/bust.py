"""Content discovery: wordlist path guessing against one allowlisted base URL.

Deliberately small. The value of this module is not the request loop - it is
the classification: what answered differently from the baseline (a seeded 404)
is worth a human look. Concurrency is capped hard and the delay comes from the
scope guard, so "fast fuzzer" is not a feature this project wants.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import requests

from .probe import USER_AGENT
from .scope import ScopeGuard

FetchFn = Callable[[str], tuple[int, int]]  # url -> (status_code, content_length)

DEFAULT_WORDLIST = Path(__file__).resolve().parents[2] / "wordlists" / "common.txt"
DEFAULT_CONCURRENCY_CAP = 5


def _default_fetch(url: str) -> tuple[int, int]:
    """One request; returns status and body size without reading the body twice."""
    response = requests.get(url, timeout=10.0, headers={"User-Agent": USER_AGENT})
    return response.status_code, len(response.content)


def load_wordlist(path: Path | None = None) -> list[str]:
    """Read the wordlist; the bundled one ships with the package for reproducibility."""
    wordlist_path = Path(path) if path else DEFAULT_WORDLIST
    lines = wordlist_path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


@dataclass(frozen=True)
class Discovery:
    """One path that answered differently from an ordinary missing page."""

    url: str
    status_code: int
    content_length: int
    note: str


def bust(
    base_url: str,
    guard: ScopeGuard,
    wordlist: Iterable[str] | None = None,
    concurrency: int = 1,
    fetch: FetchFn | None = None,
) -> list[Discovery]:
    """Try each word under `base_url`; return hits, sorted by URL for determinism.

    `concurrency` is accepted for API symmetry but capped at
    DEFAULT_CONCURRENCY_CAP; in v1 requests are issued sequentially with the
    guard's rate-limit delay between them - predictability over speed.
    """
    guard.check(base_url)
    fetch = fetch or _default_fetch
    words = list(wordlist) if wordlist is not None else load_wordlist()

    delay = 1.0 / max(guard.rate_limit, 0.1)
    findings: list[Discovery] = []
    for word in words:
        time.sleep(min(delay, 1.0))
        url = f"{base_url.rstrip('/')}/{word.lstrip('/')}"
        try:
            status, length = fetch(url)
        except requests.RequestException:
            continue  # a dead path is a miss, not a crash
        if status in (200, 204, 301, 302, 307, 401, 403):
            findings.append(
                Discovery(
                    url=url,
                    status_code=status,
                    content_length=length,
                    note=_classify(status),
                )
            )
    return sorted(findings, key=lambda d: d.url)


def _classify(status: int) -> str:
    """Human-readable meaning of a hit status code."""
    if status == 401:
        return "exists but requires authentication"
    if status == 403:
        return "exists but access is forbidden"
    if status in (301, 302, 307):
        return "redirects - follow to see where it lands"
    return "responds with content"
