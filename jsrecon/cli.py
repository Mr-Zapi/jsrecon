"""Command-line entry point: Burp XML -> endpoint reports (no web UI)."""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import http_build, openapi, pipeline
from .filters import apply_filter


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="jsrecon",
        description="Extract endpoints from JS + observed traffic in a Burp XML export.",
    )
    ap.add_argument("xml", help="path to Burp Suite XML export")
    ap.add_argument("-j", "--json", help="write JSON report to this path")
    ap.add_argument("-m", "--md", help="write Markdown report to this path")
    ap.add_argument("-o", "--openapi", help="write OpenAPI 3.0 spec to this path")
    ap.add_argument("-f", "--filter", default="", help="filter expression, e.g. 'category=api && has_param'")
    ap.add_argument("--no-inline", action="store_true", help="skip inline <script>")
    ap.add_argument("--no-traffic", action="store_true", help="skip observed Burp requests")
    ap.add_argument("--no-secrets", action="store_true", help="skip secret scan (jsluice + trufflehog)")
    ap.add_argument("--no-semgrep", action="store_true", help="skip semgrep SAST")
    ap.add_argument("--verify-secrets", action="store_true", help="trufflehog: verify secrets are live (network)")
    ap.add_argument("--no-sourcemaps", action="store_true", help="skip source map reconstruction")
    ap.add_argument("--fetch-maps", action="store_true", help="fetch remote .map files over network")
    ap.add_argument("--webpack", action="store_true", help="enumerate + fetch webpack chunks (network)")
    ap.add_argument("--include-static", action="store_true", help="keep static assets")
    ap.add_argument("-I", "--ignore-strings", action="store_true")
    ap.add_argument("-c", "--concurrency", type=int, default=8)
    args = ap.parse_args(argv)

    t0 = time.time()
    res = pipeline.run_recon(
        args.xml, include_inline=not args.no_inline,
        include_traffic=not args.no_traffic, do_secrets=not args.no_secrets,
        do_semgrep=not args.no_semgrep, verify_secrets=args.verify_secrets,
        sourcemaps_expand=not args.no_sourcemaps, fetch_remote_maps=args.fetch_maps,
        webpack_expand=args.webpack,
        ignore_strings=args.ignore_strings, concurrency=args.concurrency,
        progress=lambda s, n: print(f"  {s}: {n}    ", end="\r", file=sys.stderr),
    )
    eps = res.endpoints
    if not args.include_static:
        eps = [e for e in eps if not e.is_static]
    if args.filter:
        eps = apply_filter(eps, args.filter)

    meta = {"source": args.xml, "js_files": res.js_count,
            "observed": res.observed_count, "filter": args.filter or "(none)"}
    print(f"\n[+] {len(eps)} endpoints, {len(res.findings)} findings "
          f"in {time.time() - t0:.1f}s", file=sys.stderr)

    if args.json:
        open(args.json, "w", encoding="utf-8").write(
            http_build.to_json_report(eps, meta, res.findings))
        print(f"[+] JSON    -> {args.json}", file=sys.stderr)
    if args.md:
        open(args.md, "w", encoding="utf-8").write(
            http_build.to_markdown_report(eps, meta, res.findings))
        print(f"[+] MD      -> {args.md}", file=sys.stderr)
    if args.openapi:
        json.dump(openapi.build(res.endpoints), open(args.openapi, "w", encoding="utf-8"),
                  indent=2, ensure_ascii=False)
        print(f"[+] OpenAPI -> {args.openapi}", file=sys.stderr)
    if not (args.json or args.md or args.openapi):
        print(http_build.to_json_report(eps, meta, res.findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
