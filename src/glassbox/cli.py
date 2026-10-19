"""Command-line interface: the only supported entry point for operators.

Every command requires --scope. There is intentionally no --force, --no-scope,
or --ignore-allowlist flag: if a target is out of scope the fix belongs in the
scope file, not in a bypass flag.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .bust import bust
from .crawler import crawl
from .probe import Finding, probe
from .report import to_json, to_markdown
from .scope import ScopeGuard, ScopeViolation
from .secrets import scan_file


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glassbox",
        description="Glassbox Recon - scope-gated, readable reconnaissance primitives.",
    )
    parser.add_argument("--version", action="version", version=f"glassbox {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_scope(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--scope", required=True, type=Path, help="Path to the engagement scope JSON."
        )

    def add_output(p: argparse.ArgumentParser) -> None:
        p.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")

    p_probe = sub.add_parser("probe", help="Fetch one URL and audit its response headers.")
    p_probe.add_argument("url")
    add_scope(p_probe)
    add_output(p_probe)

    p_secrets = sub.add_parser("secrets", help="Scan a file for hardcoded credentials.")
    p_secrets.add_argument("path", type=Path)
    add_scope(p_secrets)
    add_output(p_secrets)

    p_crawl = sub.add_parser("crawl", help="BFS-crawl one site for endpoints and parameters.")
    p_crawl.add_argument("url")
    add_scope(p_crawl)
    p_crawl.add_argument("--max-depth", type=int, default=2)
    p_crawl.add_argument("--max-pages", type=int, default=40)
    add_output(p_crawl)

    p_bust = sub.add_parser("bust", help="Content discovery against one allowlisted base URL.")
    p_bust.add_argument("url")
    add_scope(p_bust)
    p_bust.add_argument("--wordlist", type=Path, default=None)
    add_output(p_bust)

    return parser


def _emit(findings: list[Finding], target: str, engagement: str, as_json: bool) -> None:
    print(
        to_json(findings, target, engagement)
        if as_json
        else to_markdown(findings, target, engagement)
    )


def main(argv: list[str] | None = None) -> int:
    """Run one command. Returns a process exit code; never raises past this point."""
    args = _build_parser().parse_args(argv)
    try:
        guard = ScopeGuard(args.scope)

        if args.command == "probe":
            result = probe(args.url, guard)
            if args.json:
                _emit(list(result.findings), result.final_url, guard.engagement, True)
            else:
                print(
                    f"probed {result.final_url} -> {result.status_code} "
                    f"({result.latency_ms} ms, server={result.server or 'unknown'})"
                )
                if result.tls_subject:
                    print(
                        f"tls: subject={result.tls_subject} issuer={result.tls_issuer} "
                        f"not_after={result.tls_not_after}"
                    )
                _emit(list(result.findings), result.final_url, guard.engagement, False)

        elif args.command == "secrets":
            findings = scan_file(args.path)
            _emit(findings, str(args.path), guard.engagement, args.json)

        elif args.command == "crawl":
            result = crawl(args.url, guard, max_depth=args.max_depth, max_pages=args.max_pages)
            if args.json:
                import json

                print(
                    json.dumps(
                        {
                            "seed": result.seed,
                            "visited": result.visited,
                            "endpoints": result.endpoints,
                            "parameters": result.parameters,
                            "skipped_offsite": result.skipped_offsite,
                            "errors": result.errors,
                        },
                        indent=2,
                    )
                )
            else:
                print(
                    f"crawled {len(result.visited)} page(s), "
                    f"{len(result.endpoints)} unique endpoint(s), "
                    f"{len(result.parameters)} URL(s) with parameters"
                )
                for endpoint in result.endpoints:
                    params = result.parameters.get(endpoint, [])
                    suffix = f"  params: {', '.join(params)}" if params else ""
                    print(f"  {endpoint}{suffix}")
                if result.skipped_offsite:
                    print(f"skipped off-site: {len(result.skipped_offsite)} URL(s)")

        elif args.command == "bust":
            words = None
            if args.wordlist:
                from .bust import load_wordlist

                words = load_wordlist(args.wordlist)
            discoveries = bust(args.url, guard, wordlist=words)
            if args.json:
                import json
                from dataclasses import asdict

                print(json.dumps([asdict(d) for d in discoveries], indent=2))
            else:
                print(f"{len(discoveries)} hit(s) under {args.url}")
                for item in discoveries:
                    print(
                        f"  {item.status_code} {item.content_length:>6}B  {item.url}  ({item.note})"
                    )

        return 0

    except ScopeViolation as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"file not found: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
