"""Run jsluice over extracted JS and aggregate endpoints."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
from typing import Iterable, Optional
from .urlutil import safe_urljoin as urljoin, safe_urlsplit as urlsplit

from . import classify
from .models import Endpoint, JsFile

JSLUICE_BIN = os.environ.get("JSLUICE_BIN", os.path.expanduser("~/go/bin/jsluice"))


UNKNOWN_HOST = "?"   # host of an endpoint that came from a relative path in JS


def _resolve(base: str, raw: str) -> str:
    """Resolve a URL found in JS against the base URL of the JS file."""
    if not raw:
        return base
    if raw.startswith(("http://", "https://")):
        return raw
    if raw.startswith("//"):
        scheme = urlsplit(base).scheme or "https"
        return f"{scheme}:{raw}"
    try:
        return urljoin(base, raw)
    except Exception:
        return raw


class Aggregator:
    """Deduplicates endpoints across many JS files."""

    def __init__(self) -> None:
        self._by_key: dict[str, Endpoint] = {}

    def add(self, ep: Endpoint) -> None:
        k = ep.key()
        existing = self._by_key.get(k)
        if existing is None:
            self._by_key[k] = ep
            return
        # merge
        existing.query_params = sorted(set(existing.query_params) | set(ep.query_params))
        existing.body_params = sorted(set(existing.body_params) | set(ep.body_params))
        existing.headers.update(ep.headers)
        for f in ep.found_in:
            if f not in existing.found_in:
                existing.found_in.append(f)
        if not existing.content_type and ep.content_type:
            existing.content_type = ep.content_type

    def endpoints(self) -> list[Endpoint]:
        return sorted(self._by_key.values(), key=lambda e: (e.host, e.path, e.method))


def _endpoint_from_jsluice(rec: dict, base_url: str) -> Optional[Endpoint]:
    raw_url = rec.get("url") or ""
    if not raw_url:
        return None
    resolved = _resolve(base_url, raw_url)
    parts = urlsplit(resolved)
    method = (rec.get("method") or "GET").upper() or "GET"
    # A relative path in JS ("/api/x") has NO host of its own — in the real SPA
    # the browser resolves it against the *page* origin, not the CDN the bundle
    # was served from. So only trust a host when the URL in JS was absolute or
    # protocol-relative; otherwise mark host unknown ("?") to be rebased later.
    absolute = raw_url.startswith(("http://", "https://", "//"))
    host = parts.netloc if absolute else UNKNOWN_HOST
    return Endpoint(
        url=resolved,
        raw_url=raw_url,
        method=method,
        query_params=list(rec.get("queryParams") or []),
        body_params=list(rec.get("bodyParams") or []),
        headers=dict(rec.get("headers") or {}),
        content_type=rec.get("contentType") or "",
        detect_type=rec.get("type") or "",
        found_in=[base_url],
        host=host,
        scheme=parts.scheme or "https",
        path=parts.path or "/",
    )


def enrich(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Classify static/api, extract query params, apply gf tags."""
    gf = classify.load_gf_patterns()
    for ep in endpoints:
        classify.classify(ep)
        classify.tag_endpoint(ep, gf)
    return endpoints


def collapse(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Merge endpoints that differ only in id-like path segments or param VALUES.

    Key = method + host + path_template + param NAMES (values ignored). Keeps one
    concrete example URL (for replay) and counts how many were collapsed. Requires
    enrich() to have run first (sets path_template)."""
    groups: dict[str, Endpoint] = {}
    for ep in endpoints:
        tmpl = ep.path_template or ep.path
        key = (f"{ep.method.upper()} {ep.scheme}://{ep.host}{tmpl}"
               f"?q={','.join(sorted(ep.query_params))}"
               f"&b={','.join(sorted(ep.body_params))}")
        rep = groups.get(key)
        if rep is None:
            groups[key] = ep
            continue
        rep.count += ep.count
        rep.query_params = sorted(set(rep.query_params) | set(ep.query_params))
        rep.body_params = sorted(set(rep.body_params) | set(ep.body_params))
        rep.tags = sorted(set(rep.tags) | set(ep.tags))
        rep.headers.update(ep.headers)
        for f in ep.found_in:
            if f not in rep.found_in:
                rep.found_in.append(f)
        if not rep.content_type and ep.content_type:
            rep.content_type = ep.content_type
    return sorted(groups.values(), key=lambda e: (e.host, e.path_template, e.method))


def analyze(
    js_files: Iterable[JsFile],
    concurrency: int = 8,
    ignore_strings: bool = False,
    progress: Optional[callable] = None,
    do_enrich: bool = True,
) -> list[Endpoint]:
    """Materialize JS to a temp dir, run jsluice, return aggregated endpoints."""
    agg = Aggregator()
    with tempfile.TemporaryDirectory(prefix="jsrecon_") as tmp:
        base_map: dict[str, str] = {}
        paths: list[str] = []
        for i, jf in enumerate(js_files):
            name = os.path.join(tmp, f"{i:07d}.js")
            try:
                with open(name, "w", encoding="utf-8") as fh:
                    fh.write(jf.source)
            except Exception:
                continue
            base_map[name] = jf.base_url()
            paths.append(name)
            if progress and i % 500 == 0:
                progress("js-write", i)

        if not paths:
            return []

        cmd = [JSLUICE_BIN, "urls", "-c", str(concurrency)]
        if ignore_strings:
            cmd.append("-I")

        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
        )
        assert proc.stdin and proc.stdout

        # Feed filenames from a separate thread: jsluice interleaves reading
        # stdin with writing stdout, so writing everything up-front would
        # deadlock once both pipe buffers fill.
        def _feed():
            try:
                for p in paths:
                    proc.stdin.write(p + "\n")
                proc.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                proc.stdin.close()

        feeder = threading.Thread(target=_feed, daemon=True)
        feeder.start()

        n = 0
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            base = base_map.get(rec.get("filename", ""), "")
            ep = _endpoint_from_jsluice(rec, base)
            if ep:
                agg.add(ep)
                n += 1
                if progress and n % 1000 == 0:
                    progress("jsluice", n)
        proc.wait()
        feeder.join(timeout=5)

    endpoints = agg.endpoints()
    if do_enrich:
        enrich(endpoints)
    return endpoints


def analyze_files(
    paths: list[str],
    base_map: dict,
    concurrency: int = 8,
    ignore_strings: bool = False,
    do_enrich: bool = False,
) -> list[Endpoint]:
    """Run jsluice directly over files that ALREADY exist on disk (a corpus
    part-subdir) — no temp copy, no sources held in memory. base_map maps each
    full file path to its original URL."""
    agg = Aggregator()
    if not paths:
        return []
    cmd = [JSLUICE_BIN, "urls", "-c", str(concurrency)]
    if ignore_strings:
        cmd.append("-I")
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True)
    assert proc.stdin and proc.stdout

    def _feed():
        try:
            for p in paths:
                proc.stdin.write(p + "\n")
            proc.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            proc.stdin.close()

    feeder = threading.Thread(target=_feed, daemon=True)
    feeder.start()
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        base = base_map.get(rec.get("filename", ""), "")
        ep = _endpoint_from_jsluice(rec, base)
        if ep:
            agg.add(ep)
    proc.wait()
    feeder.join(timeout=5)
    endpoints = agg.endpoints()
    if do_enrich:
        enrich(endpoints)
    return endpoints
