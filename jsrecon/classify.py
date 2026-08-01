"""Endpoint enrichment: static vs API classification, param extraction, gf tags."""
from __future__ import annotations

import glob
import json
import os
import re
from urllib.parse import parse_qs
from .urlutil import safe_urlsplit as urlsplit

from .models import Endpoint

# Extensions we treat as static assets / noise (images, media, fonts, styles…).
STATIC_EXT = {
    # images
    "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp", "tiff",
    # media
    "mp4", "webm", "mov", "avi", "mkv", "mp3", "wav", "ogg", "m4a", "flac",
    # fonts
    "woff", "woff2", "ttf", "otf", "eot",
    # styles / maps / docs
    "css", "scss", "less", "map", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
    "pptx", "apk", "ipa", "dmg", "exe", "zip", "gz", "rar", "7z", "tar",
    # client-side assets — a .js/.json URL is a file, not a server-side endpoint
    "js", "mjs", "json", "wasm",
}

# path markers that strongly suggest an API endpoint
_API_PATH_RE = re.compile(
    r"(/api/|/v\d+/|/rest/|/graphql|/gql|/rpc|/oauth|/oauth2/|/auth/|"
    r"/token|/session|/webhook)", re.IGNORECASE
)
_EXT_RE = re.compile(r"\.([a-z0-9]{1,6})(?:$|[?#])", re.IGNORECASE)

# path segments that look like IDs (collapsed to {id} for de-duplication)
_ID_SEG_RE = re.compile(
    r"^(?:"
    r"\d+"                                   # numeric id
    r"|[0-9a-fA-F]{8,}"                      # hex / hash
    r"|[0-9a-fA-F-]{16,}"                    # uuid-ish
    r"|[A-Za-z0-9_-]{24,}"                   # long slug / token
    r")$"
)


def normalize_path(path: str) -> str:
    """Replace id-like path segments with {id} so /orders/1 and /orders/2 merge."""
    segs = path.split("/")
    out = []
    for s in segs:
        out.append("{id}" if _ID_SEG_RE.match(s) else s)
    return "/".join(out)


def _ext(path: str) -> str:
    m = _EXT_RE.search(path.lower())
    return m.group(1) if m else ""


def classify(ep: Endpoint) -> None:
    """Mutate the endpoint in place: fill query params, category, flags."""
    parts = urlsplit(ep.url)

    # pull query params straight out of the URL string (jsluice misses some)
    if parts.query:
        for k in parse_qs(parts.query, keep_blank_values=True):
            if k and k not in ep.query_params:
                ep.query_params.append(k)
    ep.query_params.sort()

    ep.path_template = normalize_path(parts.path or "/")
    ext = _ext(parts.path)
    ep.is_static = ext in STATIC_EXT

    json_ct = "json" in (ep.content_type or "").lower()
    ep.is_api = bool(
        _API_PATH_RE.search(parts.path)
        or json_ct
        or ep.method.upper() not in ("GET", "")
        or (ep.body_params and not ep.is_static)
    )

    if ep.is_static:
        ep.category = "static"
    elif ep.is_api:
        ep.category = "api"
    else:
        ep.category = "page"


# --------------------------- gf pattern tagging ---------------------------

_GF_CACHE: dict[str, list[re.Pattern]] | None = None

# noisy/informational gf patterns we skip by default (pure noise on big sets)
_GF_SKIP = {"interestingsubs", "img-traversal", "interestingEXT", "jsvar"}


def load_gf_patterns(gf_dir: str | None = None) -> dict[str, list[re.Pattern]]:
    """Load ~/.gf/*.json pattern files into compiled regexes, keyed by name."""
    global _GF_CACHE
    if _GF_CACHE is not None:
        return _GF_CACHE
    gf_dir = gf_dir or os.environ.get("GF_DIR", os.path.expanduser("~/.gf"))
    out: dict[str, list[re.Pattern]] = {}
    for fp in glob.glob(os.path.join(gf_dir, "*.json")):
        name = os.path.splitext(os.path.basename(fp))[0]
        if name in _GF_SKIP:
            continue
        try:
            spec = json.load(open(fp, encoding="utf-8"))
        except Exception:
            continue
        flags = re.IGNORECASE if "i" in spec.get("flags", "") else 0
        pats = spec.get("patterns") or ([spec["pattern"]] if spec.get("pattern") else [])
        compiled = []
        for p in pats:
            try:
                compiled.append(re.compile(p, flags))
            except re.error:
                continue
        if compiled:
            out[name] = compiled
    _GF_CACHE = out
    return out


def tag_endpoint(ep: Endpoint, patterns: dict[str, list[re.Pattern]]) -> None:
    """Attach gf class tags (redirect, lfi, rce, idor…) based on URL + params."""
    # build a haystack of param=value style tokens so `param=` patterns match
    hay = ep.url
    extra = "".join(f"?{p}=&" for p in (ep.query_params + ep.body_params))
    hay = hay + " " + extra
    tags = set(ep.tags)
    for name, pats in patterns.items():
        for pat in pats:
            if pat.search(hay):
                tags.add(name)
                break
    ep.tags = sorted(tags)
