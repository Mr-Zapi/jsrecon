"""Orchestrator: Burp XML -> JS endpoints + observed traffic + secrets."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import analyzer, burp_parser, corpus, sast, sourcemaps, webpack
from .analyzer import Aggregator, collapse, enrich
from .models import Endpoint, Finding


def _make_http_fetch(proxy: str = ""):
    """Build a blocking map/chunk downloader for the Burp flow (no browser session).
    Routes through `proxy` when set; downloads directly when it's empty."""
    def _fetch(url: str):
        try:
            import httpx
            kw = dict(timeout=15, follow_redirects=True, verify=False)
            if proxy:
                kw["proxy"] = proxy
            r = httpx.get(url, **kw)
            return r.content if r.status_code == 200 else None
        except Exception:
            return None
    return _fetch


# default (no-proxy) fetcher for callers that don't thread a proxy through
_http_fetch = _make_http_fetch("")


@dataclass
class ReconResult:
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    js_count: int = 0
    observed_count: int = 0


def run_recon_js(
    js_files: list,
    do_secrets: bool = True,
    do_semgrep: bool = True,
    verify_secrets: bool = False,
    concurrency: int = 8,
    progress: Optional[Callable] = None,
) -> ReconResult:
    """Analyze a ready list of JsFile (e.g. from katana) — jsluice + SAST."""
    def p(stage, n):
        if progress:
            progress(stage, n)

    p("js-write", len(js_files))
    endpoints = analyzer.analyze(
        js_files, concurrency=concurrency, do_enrich=True,
        progress=lambda k, n: p(k, n),
    )
    endpoints = collapse(endpoints)
    findings = sast.run_sast(
        js_files, do_secrets=do_secrets, do_semgrep=do_semgrep,
        verify_secrets=verify_secrets, concurrency=concurrency, progress=p,
    ) if (do_secrets or do_semgrep) else []
    return ReconResult(
        endpoints=endpoints, findings=findings,
        js_count=len(js_files), observed_count=0,
    )


def run_recon_corpus(
    corpus_path: str,
    do_secrets: bool = True,
    do_semgrep: bool = True,
    verify_secrets: bool = False,
    concurrency: int = 8,
    progress: Optional[Callable] = None,
    should_stop: Optional[Callable] = None,
) -> ReconResult:
    """Analyze a persisted corpus ONE part-subdir at a time so peak memory is
    bounded to a single batch (~500 files) instead of the whole corpus. This is
    what keeps a 15k-file run from OOM-killing the server."""
    def p(stage, n):
        if progress:
            progress(stage, n)

    agg = Aggregator()
    findings: dict[str, Finding] = {}
    n_files = 0
    stop = should_stop or (lambda: False)
    parts = corpus.part_paths(corpus_path)
    for bi, pdir in enumerate(parts, 1):
        if stop():
            break
        base_map = corpus.dir_manifest(pdir)   # {full_path: url}, no file bodies read
        if not base_map:
            continue
        n_files += len(base_map)
        p("batch", f"{bi}/{len(parts)} {pdir} ({len(base_map)} JS)")
        paths = list(base_map.keys())
        # jsluice + SAST run DIRECTLY on the files on disk — nothing in RAM
        for e in analyzer.analyze_files(paths, base_map, concurrency=concurrency):
            agg.add(e)
        if do_secrets or do_semgrep:
            for f in sast.run_sast_dir(pdir, base_map, do_secrets=do_secrets,
                                       do_semgrep=do_semgrep, verify_secrets=verify_secrets,
                                       concurrency=concurrency):
                findings[f.key()] = f
        p("batch-done", f"part {bi}/{len(parts)} done - {n_files} JS, {len(findings)} findings")

    endpoints = agg.endpoints()
    enrich(endpoints)
    endpoints = collapse(endpoints)
    return ReconResult(endpoints=endpoints, findings=list(findings.values()),
                       js_count=n_files, observed_count=0)


def run_recon(
    xml_path: str,
    include_inline: bool = True,
    include_traffic: bool = True,
    ignore_strings: bool = False,
    do_secrets: bool = True,
    do_semgrep: bool = True,
    verify_secrets: bool = False,
    sourcemaps_expand: bool = True,
    fetch_remote_maps: bool = False,
    webpack_expand: bool = False,
    concurrency: int = 8,
    proxy: str = "",
    progress: Optional[Callable] = None,
) -> ReconResult:
    def p(stage, n):
        if progress:
            progress(stage, n)

    http_fetch = _make_http_fetch(proxy)   # honour upstream proxy for map/chunk DLs

    # 1. extract JS (+ originals from any .map responses in the XML)
    js_files = []
    for jf in burp_parser.iter_js_files(xml_path, include_inline=include_inline,
                                        include_maps=sourcemaps_expand,
                                        progress=lambda n: p("parsing", n)):
        js_files.append(jf)

    # 1a. webpack chunk enumeration: reconstruct + fetch lazily-loaded chunks
    if webpack_expand:
        existing = {jf.base_url() for jf in js_files}
        curls = webpack.enumerate_from_js(js_files, exclude=existing)
        if curls:
            p("webpack", len(curls))
            js_files.extend(webpack.fetch_chunks_sync(
                curls, http_fetch, progress=lambda s, n: p(s, n)))

    # 1b. source maps: inline always; remote .map fetched only if asked
    if sourcemaps_expand:
        if fetch_remote_maps:
            extra = sourcemaps.expand_remote_sync(
                js_files, http_fetch, progress=lambda s, n: p(s, n))
        else:
            extra = sourcemaps.expand_inline(js_files)
        if extra:
            p("sourcemaps", len(extra))
            js_files.extend(extra)

    # 2. jsluice endpoints (unenriched, we enrich after merge)
    p("js-write", len(js_files))
    js_eps = analyzer.analyze(
        js_files, concurrency=concurrency, ignore_strings=ignore_strings,
        do_enrich=False, progress=lambda k, n: p(k, n),
    )

    # 3. merge with observed traffic through one aggregator
    agg = Aggregator()
    for e in js_eps:
        agg.add(e)
    observed = 0
    if include_traffic:
        for e in burp_parser.iter_observed_endpoints(
            xml_path, progress=lambda n: p("traffic", n)
        ):
            agg.add(e)
            observed += 1

    endpoints = agg.endpoints()
    enrich(endpoints)
    endpoints = collapse(endpoints)

    # 4. SAST (jsluice secrets + trufflehog + semgrep) over the JS corpus
    findings: list[Finding] = []
    if do_secrets or do_semgrep:
        findings = sast.run_sast(
            js_files, do_secrets=do_secrets, do_semgrep=do_semgrep,
            verify_secrets=verify_secrets, concurrency=concurrency, progress=p,
        )

    return ReconResult(
        endpoints=endpoints, findings=findings,
        js_count=len(js_files), observed_count=observed,
    )
