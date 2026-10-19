"""Same-origin crawler: BFS over one site, collecting endpoints and parameters.

Why BFS with a depth cap instead of "follow everything": a crawler that loses
the site boundary is a liability. The boundary here is the seed's registrable
host plus its subdomains, and every hop costs rate_limit seconds - politeness
is enforced by the guard, not by hope.

`fetch` is injectable so tests never touch the network: the default implementation
is one requests.get, and that is the only place a connection is opened.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .probe import USER_AGENT
from .scope import ScopeGuard

FetchFn = Callable[[str], str]

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PAGES = 40


def _default_fetch(url: str) -> str:
    """The single network touchpoint of this module."""
    response = requests.get(url, timeout=10.0, headers={"User-Agent": USER_AGENT})
    return response.text


def _same_site(host: str | None, base_host: str) -> bool:
    """True when host is base_host or any subdomain of it."""
    if not host:
        return False
    host = host.lower()
    base = base_host.lower()
    return host == base or host.endswith("." + base)


def _normalize(url: str) -> str:
    """Drop fragments (never change the resource) and keep the query for dedupe."""
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()


@dataclass
class CrawlResult:
    """What one crawl observed; later phases report on this, they do not re-fetch."""

    seed: str
    visited: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)  # unique path URLs seen in links
    parameters: dict[str, list[str]] = field(default_factory=dict)  # url -> param names
    skipped_offsite: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _extract_page(soup: BeautifulSoup, base_url: str, result: CrawlResult) -> list[str]:
    """Collect links, form actions, and query parameter names from one page."""
    candidates: list[str] = []
    for tag in soup.find_all(["a", "link", "script", "iframe", "area", "form"]):
        raw = tag.get("href") or tag.get("src") or tag.get("action")
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            continue
        absolute = _normalize(urljoin(base_url, raw))
        if urlparse(absolute).scheme not in ("http", "https"):
            continue
        candidates.append(absolute)

    # Parameter names per URL: query strings on links plus form input names.
    # Keyed by path-only URL so report lookups (endpoint -> params) match.
    for url in candidates:
        parsed = urlparse(url)
        path_key = parsed._replace(query="", fragment="").geturl()
        params = result.parameters.setdefault(path_key, [])
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            if key not in params:
                params.append(key)

    for form in soup.find_all("form"):
        action = form.get("action")
        target_url = urljoin(base_url, action) if action else base_url
        path_key = urlparse(target_url)._replace(query="", fragment="").geturl()
        params = result.parameters.setdefault(path_key, [])
        for field_tag in form.find_all(["input", "select", "textarea"]):
            name = field_tag.get("name")
            if name and name not in params:
                params.append(name)

    return candidates


def crawl(
    url: str,
    guard: ScopeGuard,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_pages: int = DEFAULT_MAX_PAGES,
    fetch: FetchFn | None = None,
) -> CrawlResult:
    """BFS-crawl `url` (scope-checked) up to max_depth / max_pages."""
    guard.check(url)
    fetch = fetch or _default_fetch

    seed = _normalize(url)
    base_host = urlparse(seed).hostname
    result = CrawlResult(seed=seed)
    queue: deque[tuple[str, int]] = deque([(seed, 0)])
    seen: set[str] = {seed}

    while queue:
        current, depth = queue.popleft()
        if len(result.visited) >= max_pages:
            break
        result.visited.append(current)

        # Politeness: one slot per request, driven by the engagement rate limit.
        delay = 1.0 / max(guard.rate_limit, 0.1)
        if delay > 0:
            time.sleep(min(delay, 2.0))

        try:
            html = fetch(current)
        except requests.RequestException as exc:
            result.errors.append(f"{current}: {exc}")
            continue

        soup = BeautifulSoup(html, "html.parser")
        for candidate in _extract_page(soup, current, result):
            host = urlparse(candidate).hostname
            if not _same_site(host, base_host):
                if candidate not in result.skipped_offsite:
                    result.skipped_offsite.append(candidate)
                continue
            path_only = urlparse(candidate)._replace(query="", fragment="").geturl()
            if path_only not in result.endpoints:
                result.endpoints.append(path_only)
            if depth < max_depth and candidate not in seen:
                seen.add(candidate)
                queue.append((candidate, depth + 1))

    return result
