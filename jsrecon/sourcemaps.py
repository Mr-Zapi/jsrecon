"""Reconstruct original source files from JavaScript source maps.

Minified prod bundles often ship (or reference) a `.map` file whose
`sourcesContent` holds the ORIGINAL un-minified files — with real names,
folder structure and comments. Feeding those to jsluice/gf/secrets finds far
more endpoints and secrets than the minified blob.

We support:
  - inline maps:   //# sourceMappingURL=data:application/json;base64,....
  - remote maps:   //# sourceMappingURL=app.abc.js.map   (fetched via a callback)
  - sibling guess: <bundle>.js -> <bundle>.js.map        (when no comment)
  - maps already captured in a Burp XML (parsed directly)
"""
from __future__ import annotations

import base64
import json
import re
from typing import Awaitable, Callable, Optional
from urllib.parse import unquote_to_bytes
from .urlutil import safe_urljoin as urljoin, safe_urlsplit as urlsplit

from .models import JsFile

_MAP_URL_RE = re.compile(
    r"(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s'\"*]+)"
)


def find_map_url(source: str) -> Optional[str]:
    """Return the last sourceMappingURL reference in a JS file, if any."""
    matches = _MAP_URL_RE.findall(source or "")
    return matches[-1].strip() if matches else None


def _decode_data_uri(uri: str) -> Optional[bytes]:
    if not uri.startswith("data:"):
        return None
    header, _, payload = uri.partition(",")
    if not payload:
        return None
    try:
        if ";base64" in header:
            return base64.b64decode(payload)
        return unquote_to_bytes(payload)
    except Exception:
        return None


def _clean_source_name(name: str) -> str:
    """Normalize a source map source path into a readable pseudo-URL."""
    n = name or ""
    # webpack://app/./src/x.js  ->  webpack://app/src/x.js
    n = n.replace("/./", "/")
    return n


def _bundle_base(url: str) -> str:
    """Given a .map (or bundle) URL, return the bundle URL to resolve against."""
    u = (url or "").split("?")[0]
    if u.endswith(".map"):
        u = u[:-4]
    return u


def parse_map(map_bytes: bytes, origin_url: str = "") -> list[JsFile]:
    """Turn a source map's sourcesContent into JsFile originals.

    The reconstructed file's `url` = "<bundle_url>#<original_path>": the bundle
    URL drives correct endpoint resolution (real host), while the fragment keeps
    the original file path visible in `found_in`.
    """
    try:
        data = json.loads(map_bytes)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    base = _bundle_base(origin_url)
    host = urlsplit(base).netloc if base else ""
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    out: list[JsFile] = []
    for i, src in enumerate(sources):
        if i >= len(contents):
            break
        content = contents[i]
        if not content or not isinstance(content, str):
            continue
        # skip vendored node_modules noise — rarely target-relevant
        if "node_modules" in (src or ""):
            continue
        name = _clean_source_name(src) or f"src{i}"
        ident = f"{base}#{name}" if base else name
        out.append(JsFile(url=ident, source=content, origin="sourcemap", host=host))
    return out


def looks_like_map(body: bytes) -> bool:
    head = body[:200].lstrip()
    return head.startswith(b"{") and b'"version"' in body[:400] and b'"sources"' in body[:2000]


def expand_inline(js_files: list[JsFile]) -> list[JsFile]:
    """Expand only inline (data:) source maps — no network needed."""
    extracted: list[JsFile] = []
    seen: set[str] = set()
    for jf in js_files:
        url = find_map_url(jf.source)
        if not url or not url.startswith("data:"):
            continue
        raw = _decode_data_uri(url)
        if not raw:
            continue
        for orig in parse_map(raw, jf.url):
            if orig.url not in seen:
                seen.add(orig.url)
                extracted.append(orig)
    return extracted


def expand_remote_sync(
    js_files: list[JsFile],
    fetch: Callable[[str], Optional[bytes]],
    try_sibling: bool = True,
    progress: Optional[Callable] = None,
) -> list[JsFile]:
    """Synchronous variant of expand_remote (for the executor-thread Burp flow).
    `fetch(url)->bytes|None` is a blocking downloader."""
    extracted: list[JsFile] = []
    seen: set[str] = set()
    done = 0
    for jf in js_files:
        raw: Optional[bytes] = None
        ref = find_map_url(jf.source)
        if ref and ref.startswith("data:"):
            raw = _decode_data_uri(ref)
        elif ref:
            raw = fetch(urljoin(jf.url, ref))
        elif try_sibling and jf.url.lower().split("?")[0].endswith((".js", ".mjs")):
            raw = fetch(jf.url.split("?")[0] + ".map")
        done += 1
        if progress and done % 50 == 0:
            progress("sourcemaps", done)
        if not raw or not looks_like_map(raw):
            continue
        for orig in parse_map(raw, jf.url):
            if orig.url not in seen:
                seen.add(orig.url)
                extracted.append(orig)
    return extracted


async def expand_remote(
    js_files: list[JsFile],
    fetch: Callable[[str], Awaitable[Optional[bytes]]],
    try_sibling: bool = True,
    progress: Optional[Callable] = None,
) -> list[JsFile]:
    """Expand inline + remote maps. `fetch(url)->bytes|None` downloads a map
    (through the browser session for auth/ServicePipe)."""
    extracted: list[JsFile] = []
    seen: set[str] = set()
    done = 0
    for jf in js_files:
        raw: Optional[bytes] = None
        ref = find_map_url(jf.source)
        if ref and ref.startswith("data:"):
            raw = _decode_data_uri(ref)
        elif ref:
            raw = await fetch(urljoin(jf.url, ref))
        elif try_sibling and jf.url.lower().split("?")[0].endswith((".js", ".mjs")):
            raw = await fetch(jf.url.split("?")[0] + ".map")
        done += 1
        if progress and done % 20 == 0:
            progress("sourcemaps", done)
        if not raw or not looks_like_map(raw):
            continue
        for orig in parse_map(raw, jf.url):
            if orig.url not in seen:
                seen.add(orig.url)
                extracted.append(orig)
    return extracted
