"""Webpack chunk enumeration.

A webpack runtime chunk contains the map(s) needed to lazy-load every other
chunk — including ones the browser never loaded (admin panels, feature-flagged
modals, unused routes). We parse the runtime's `__webpack_require__.u`
(and `.miniCssF`) to reconstruct ALL chunk URLs, then fetch the missing ones.

Heuristic: covers the common webpack 5 / Next.js shapes:
  "static/chunks/" + ((NAME[e]||e)) + "." + HASH[e] + ".js"
  "static/chunks/" + e + "." + HASH[e] + ".js"
  id===e ? "static/chunks/....js" : ...          (explicit ternary chain)
  "static/css/" + ({...}[e]) + ".css"            (miniCssF)
"""
from __future__ import annotations

import re
from typing import Callable, Optional
from .urlutil import safe_urljoin as urljoin, safe_urlsplit as urlsplit

from .models import JsFile

_MAP_RE = re.compile(r'\{((?:\d+:"[\w./@-]+")(?:,\d+:"[\w./@-]+")*)\}')
_PUBLIC_PATH_RE = re.compile(r'\.p\s*=\s*"([^"]*)"')
# explicit ternary: 4253===e?"static/chunks/xxx.js"
_TERNARY_RE = re.compile(r'\d+===\w+\?"(static/[^"]+\.(?:js|css))"')

# general JS formula with a name map + a hash map (maps may be paren-wrapped):
#   "static/chunks/"+(({NAME})[e]||e)+"."+({HASH})[e]+".js"
_JS_NAMED_RE = re.compile(
    r'"(static/chunks/)"\+\(*\{([^{}]+)\}\)*\[\w+\]\|\|\w+\)\+'
    r'"([^"]*)"\+\(*\{([^{}]+)\}\)*\[\w+\]\+"([^"]*\.js)"'
)
# without a name map:  "static/chunks/"+e+"."+({HASH})[e]+".js"
_JS_PLAIN_RE = re.compile(
    r'"(static/chunks/)"\+\w+\+"([^"]*)"\+\(*\{([^{}]+)\}\)*\[\w+\]\+"([^"]*\.js)"'
)
# miniCssF:  "static/css/"+({HASH})[e]+".css"
_CSS_RE = re.compile(
    r'"(static/css/)"\+\(*\{([^{}]+)\}\)*\[\w+\]\)*\+"([^"]*\.css)"'
)


def _parse_map(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in re.findall(r'(\d+):"([\w./@-]+)"', body):
        out[k] = v
    return out


def looks_like_runtime(source: str) -> bool:
    return ("static/chunks/" in source and
            (".u=" in source or "webpackChunk" in source or "__webpack_require__" in source))


def parse_runtime(source: str) -> dict:
    """Return {'public_path': str, 'chunks': set[str]} of relative chunk paths."""
    public_path = ""
    m = _PUBLIC_PATH_RE.search(source)
    if m:
        public_path = m.group(1)

    chunks: set[str] = set()

    # 1. explicit ternary paths
    for path in _TERNARY_RE.findall(source):
        chunks.add(path)

    # 2. general JS formula with name map + hash map
    for prefix, m1, glue, m2, suf in _JS_NAMED_RE.findall(source):
        names = _parse_map(m1)
        hashes = _parse_map(m2)
        for cid, h in hashes.items():
            name = names.get(cid, cid)
            chunks.add(f"{prefix}{name}{glue}{h}{suf}")

    # 3. general JS formula without name map
    for prefix, glue, m2, suf in _JS_PLAIN_RE.findall(source):
        for cid, h in _parse_map(m2).items():
            chunks.add(f"{prefix}{cid}{glue}{h}{suf}")

    # 4. CSS via miniCssF
    for prefix, m, suf in _CSS_RE.findall(source):
        for cid, h in _parse_map(m).items():
            chunks.add(f"{prefix}{h}{suf}")

    return {"public_path": public_path, "chunks": chunks}


def chunk_urls(runtime_url: str, source: str) -> list[str]:
    """Absolute URLs for every chunk referenced by this runtime file."""
    info = parse_runtime(source)
    if not info["chunks"]:
        return []
    pp = info["public_path"] or "/"
    base = urljoin(runtime_url, pp if pp.endswith("/") else pp + "/")
    out: list[str] = []
    seen: set[str] = set()
    for rel in info["chunks"]:
        u = urljoin(base, rel)
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def enumerate_from_js(js_files, exclude: Optional[set] = None) -> list[str]:
    """Scan JS files for a webpack runtime and return NEW chunk URLs found
    (not already present in `exclude`, e.g. URLs we already have)."""
    exclude = exclude or set()
    urls: list[str] = []
    seen: set[str] = set()
    for jf in js_files:
        if not looks_like_runtime(jf.source):
            continue
        for u in chunk_urls(jf.base_url(), jf.source):
            if u not in seen and u not in exclude:
                seen.add(u)
                urls.append(u)
    return urls


def fetch_chunks_sync(
    urls: list[str],
    fetch: Callable[[str], Optional[bytes]],
    progress: Optional[Callable] = None,
) -> list[JsFile]:
    """Download webpack chunks (blocking) into JsFile objects."""
    out: list[JsFile] = []
    for i, u in enumerate(urls):
        raw = fetch(u)
        if progress and i % 25 == 0:
            progress("webpack", i)
        if raw:
            out.append(JsFile(url=u, source=raw.decode("utf-8", "replace"),
                              origin="webpack", host=urlsplit(u).netloc))
    return out
