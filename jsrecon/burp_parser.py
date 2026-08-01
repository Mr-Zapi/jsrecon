"""Streaming parser for Burp Suite XML exports.

The export can be very large (hundreds of MB), so we use lxml.iterparse and
clear each <item> element right after processing to keep memory flat.
"""
from __future__ import annotations

import base64
import re
from typing import Iterator, Optional
from urllib.parse import parse_qs
from .urlutil import safe_urlsplit as urlsplit

from lxml import etree

from . import sourcemaps
from .models import Endpoint, JsFile

# inline <script> ... </script> without a src= attribute
_INLINE_SCRIPT_RE = re.compile(
    rb"<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_CONTENT_TYPE_RE = re.compile(rb"^content-type\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)

_JS_CT_MARKERS = ("javascript", "ecmascript", "application/json")  # json can hold urls too


def _text(item: etree._Element, tag: str) -> str:
    el = item.find(tag)
    if el is None or el.text is None:
        return ""
    return el.text


def _decoded(item: etree._Element, tag: str) -> bytes:
    el = item.find(tag)
    if el is None or el.text is None:
        return b""
    raw = el.text
    if el.get("base64") == "true":
        try:
            return base64.b64decode(raw)
        except Exception:
            return b""
    return raw.encode("utf-8", "replace")


def _split_http(blob: bytes) -> tuple[bytes, bytes]:
    """Split a raw HTTP message into (headers, body)."""
    idx = blob.find(b"\r\n\r\n")
    if idx == -1:
        idx = blob.find(b"\n\n")
        if idx == -1:
            return blob, b""
        return blob[:idx], blob[idx + 2:]
    return blob[:idx], blob[idx + 4:]


def _content_type(headers: bytes) -> str:
    m = _CONTENT_TYPE_RE.search(headers)
    return m.group(1).decode("latin-1").strip().lower() if m else ""


def iter_js_files(
    xml_path: str,
    include_inline: bool = True,
    include_maps: bool = True,
    progress: Optional[callable] = None,
) -> Iterator[JsFile]:
    """Yield JsFile objects extracted from a Burp XML export.

    - Standalone JS responses (mimetype/content-type javascript, or path *.js)
    - Inline <script> blocks inside HTML responses (if include_inline)
    - Original files reconstructed from .map responses captured in the XML
      (if include_maps) — real un-minified source via sourcesContent
    """
    count = 0
    # huge_tree: allow very large text nodes (big base64 bodies)
    # resolve_entities=False + no_network: mitigate XXE from the DOCTYPE
    context = etree.iterparse(
        xml_path,
        events=("end",),
        tag="item",
        huge_tree=True,
        resolve_entities=False,
        no_network=True,
        recover=True,
    )
    for _event, item in context:
        count += 1
        if progress and count % 500 == 0:
            progress(count)

        url = _text(item, "url").strip()
        host = _text(item, "host").strip()
        path = _text(item, "path").strip()
        mimetype = _text(item, "mimetype").strip().lower()

        resp = _decoded(item, "response")
        if resp:
            headers, body = _split_http(resp)
            ctype = _content_type(headers)

            clean_path = path.lower().split("?")[0]
            is_map = clean_path.endswith(".map")
            is_js = (
                not is_map and (
                    mimetype in ("script", "javascript")
                    or any(m in ctype for m in _JS_CT_MARKERS)
                    or clean_path.endswith(".js")
                )
            )
            is_html = "html" in ctype or mimetype == "html"

            if include_maps and is_map and body.strip() and sourcemaps.looks_like_map(body):
                for orig in sourcemaps.parse_map(body, url):
                    yield orig
            elif is_js and body.strip():
                yield JsFile(
                    url=url or path,
                    source=body.decode("utf-8", "replace"),
                    origin="response",
                    host=host,
                    mimetype=ctype or mimetype,
                )
            elif include_inline and is_html and body.strip():
                for m in _INLINE_SCRIPT_RE.finditer(body):
                    script = m.group(1)
                    if script.strip():
                        yield JsFile(
                            url=url or path,
                            source=script.decode("utf-8", "replace"),
                            origin="inline",
                            host=host,
                            mimetype="text/html (inline)",
                        )

        # free memory: clear this element and any preceding siblings
        item.clear()
        parent = item.getparent()
        if parent is not None:
            while item.getprevious() is not None:
                del parent[0]

    del context
    if progress:
        progress(count)


def _body_params(headers: bytes, body: bytes) -> tuple[list[str], str]:
    """Extract parameter names from a request body."""
    ct = _content_type(headers)
    text = body.decode("utf-8", "replace").strip()
    if not text:
        return [], ct
    if "json" in ct or (text.startswith("{") and text.endswith("}")):
        try:
            import json
            obj = json.loads(text)
            if isinstance(obj, dict):
                return list(obj.keys()), ct or "application/json"
        except Exception:
            pass
    if "form-urlencoded" in ct or ("=" in text and "\n" not in text[:200]):
        keys = [kv.split("=", 1)[0] for kv in text.split("&") if kv and "=" in kv]
        return [k for k in keys if k], ct or "application/x-www-form-urlencoded"
    return [], ct


def iter_observed_endpoints(
    xml_path: str, progress: Optional[callable] = None
) -> Iterator[Endpoint]:
    """Yield Endpoints from the *actual* requests Burp recorded (real params)."""
    count = 0
    context = etree.iterparse(
        xml_path, events=("end",), tag="item",
        huge_tree=True, resolve_entities=False, no_network=True, recover=True,
    )
    for _event, item in context:
        count += 1
        if progress and count % 500 == 0:
            progress(count)

        url = _text(item, "url").strip()
        method = _text(item, "method").strip().upper() or "GET"
        if not url:
            item.clear()
            continue
        parts = urlsplit(url)
        qparams = sorted(parse_qs(parts.query, keep_blank_values=True).keys()) if parts.query else []

        bparams: list[str] = []
        ctype = ""
        req = _decoded(item, "request")
        if req:
            rheaders, rbody = _split_http(req)
            bparams, ctype = _body_params(rheaders, rbody)

        yield Endpoint(
            url=url, raw_url=url, method=method,
            query_params=qparams, body_params=sorted(set(bparams)),
            content_type=ctype, detect_type="burp-traffic",
            found_in=["burp: observed traffic"],
            host=parts.netloc, scheme=parts.scheme or "https",
            path=parts.path or "/",
        )

        item.clear()
        parent = item.getparent()
        if parent is not None:
            while item.getprevious() is not None:
                del parent[0]
    if progress:
        progress(count)


def count_items(xml_path: str) -> int:
    """Cheap-ish count of <item> elements (still streams the file)."""
    n = 0
    context = etree.iterparse(
        xml_path, events=("end",), tag="item",
        huge_tree=True, resolve_entities=False, no_network=True, recover=True,
    )
    for _e, item in context:
        n += 1
        item.clear()
        parent = item.getparent()
        if parent is not None:
            while item.getprevious() is not None:
                del parent[0]
    return n
