"""Build Burp-style raw HTTP requests and report outputs from endpoints."""
from __future__ import annotations

import json
from urllib.parse import urlencode
from .urlutil import safe_urlsplit as urlsplit

from .models import Endpoint

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
)


def build_body(ep: Endpoint) -> tuple[str, str]:
    """Return (body, content_type) for the endpoint's body params."""
    if not ep.body_params:
        return "", ep.content_type
    ct = (ep.content_type or "").lower()
    if "json" in ct:
        obj = {p: "" for p in ep.body_params}
        return json.dumps(obj), ep.content_type or "application/json"
    # default form-encoded
    body = urlencode({p: "" for p in ep.body_params})
    return body, ep.content_type or "application/x-www-form-urlencoded"


def build_query(ep: Endpoint) -> str:
    parts = urlsplit(ep.url)
    existing = parts.query
    present = {kv.split("=", 1)[0] for kv in existing.split("&") if kv}
    missing = [p for p in ep.query_params if p not in present]
    extra = urlencode({p: "" for p in missing}) if missing else ""
    if existing and extra:
        return f"{existing}&{extra}"
    return existing or extra


def raw_request(ep: Endpoint, cookie: str = "") -> str:
    """Render a Burp-style raw HTTP/1.1 request string.

    If `cookie` is given (e.g. harvested from the live browser session), it is
    added as a Cookie header so the displayed request is already authenticated.
    """
    parts = urlsplit(ep.url)
    host = parts.netloc or ep.host
    path = parts.path or "/"
    query = build_query(ep)
    target = f"{path}?{query}" if query else path

    body, ctype = build_body(ep)

    headers: dict[str, str] = {}
    headers["Host"] = host
    headers["User-Agent"] = DEFAULT_UA
    headers["Accept"] = "*/*"
    for k, v in ep.headers.items():
        headers[k] = v
    if cookie:
        headers["Cookie"] = cookie
    if body:
        headers["Content-Type"] = ctype
        headers["Content-Length"] = str(len(body.encode("utf-8")))
    headers["Connection"] = "close"

    lines = [f"{ep.method} {target} HTTP/1.1"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = "\r\n".join(lines) + "\r\n\r\n"
    if body:
        raw += body
    return raw


def to_json_report(endpoints: list[Endpoint], meta: dict | None = None,
                   findings: list | None = None) -> str:
    return json.dumps(
        {
            "meta": meta or {},
            "count": len(endpoints),
            "endpoints": [ep.to_dict() for ep in endpoints],
            "findings": [f.to_dict() for f in (findings or [])],
        },
        indent=2,
        ensure_ascii=False,
    )


def to_markdown_report(endpoints: list[Endpoint], meta: dict | None = None,
                       findings: list | None = None) -> str:
    lines = ["# jsrecon — Endpoint report", ""]
    if meta:
        for k, v in meta.items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")
    lines.append(f"Total endpoints: **{len(endpoints)}**")
    lines.append("")

    if findings:
        lines.append(f"## 🔐 Findings (SAST) — {len(findings)}")
        lines.append("")
        for f in findings:
            lines.append(f"- **[{f.severity}]** `{f.kind}` — `{f.evidence}`  "
                         f"({f.source}) @ {f.location}")
        lines.append("")

    # group by host
    by_host: dict[str, list[Endpoint]] = {}
    for ep in endpoints:
        by_host.setdefault(ep.host or "(relative)", []).append(ep)

    for host in sorted(by_host):
        lines.append(f"## {host}")
        lines.append("")
        for ep in by_host[host]:
            lines.append(f"### `{ep.method} {ep.path}`")
            lines.append("")
            lines.append(f"- URL: `{ep.url}`")
            lines.append(f"- Category: `{ep.category}`" +
                         (f" · tags: {', '.join(f'`{t}`' for t in ep.tags)}" if ep.tags else ""))
            if ep.query_params:
                lines.append(f"- Query params: {', '.join(f'`{p}`' for p in ep.query_params)}")
            if ep.body_params:
                lines.append(f"- Body params: {', '.join(f'`{p}`' for p in ep.body_params)}")
            if ep.content_type:
                lines.append(f"- Content-Type: `{ep.content_type}`")
            if ep.detect_type:
                lines.append(f"- Detected via: `{ep.detect_type}`")
            if ep.found_in:
                lines.append(f"- Found in: {', '.join(f'`{f}`' for f in ep.found_in[:5])}")
            lines.append("")
            lines.append("```http")
            lines.append(raw_request(ep).replace("\r\n", "\n").rstrip())
            lines.append("```")
            lines.append("")
    return "\n".join(lines)
