"""MCP server exposing jsrecon to an LLM.

It is a thin client over the running jsrecon FastAPI server (default
http://127.0.0.1:8777), so the LLM sees the same live jobs and shares the same
human-opened browser session. The model can browse endpoints/params/secrets/gf
findings and *send* requests that ride the browser session's cookies — and it
decides when to re-read fresh cookies.

Run:
    JSRECON_URL=http://127.0.0.1:8777 python -m jsrecon.mcp_server
"""
from __future__ import annotations

import os
from typing import Any, Optional, Union

import httpx
from mcp.server.fastmcp import FastMCP

BASE = os.environ.get("JSRECON_URL", "http://127.0.0.1:8777")


def _read_token() -> str:
    t = os.environ.get("JSRECON_TOKEN")
    if t:
        return t
    # fall back to the token the server persisted (no env var needed)
    try:
        from . import store
        with open(os.path.join(store.DATA_DIR, "token"), encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return ""


TOKEN = _read_token()
_HEADERS = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
mcp = FastMCP("jsrecon")


async def _get(path: str, **params):
    async with httpx.AsyncClient(base_url=BASE, timeout=60, trust_env=False,
                                 headers=_HEADERS) as c:
        r = await c.get(path, params={k: v for k, v in params.items() if v is not None})
        r.raise_for_status()
        return r.json()


async def _post(path: str, json: dict):
    async with httpx.AsyncClient(base_url=BASE, timeout=120, trust_env=False,
                                 headers=_HEADERS) as c:
        r = await c.post(path, json=json)
        r.raise_for_status()
        return r.json()


@mcp.tool()
async def analyze(path: str, include_traffic: bool = True, do_secrets: bool = True) -> dict:
    """Start analysis of a Burp XML export on the server. Returns the job id."""
    return await _post("/api/analyze", {
        "path": path, "include_traffic": include_traffic, "do_secrets": do_secrets,
    })


@mcp.tool()
async def katana(domain: str, depth: int = 2, use_session: bool = True) -> dict:
    """Crawl a domain with katana for JS, download, analyze; merges into project."""
    return await _post("/api/katana", {"domain": domain, "depth": depth,
                                       "use_session": use_session})


@mcp.tool()
async def archive(domain: str, use_gau: bool = True, use_wayback: bool = True,
                  subs: bool = True) -> dict:
    """Collect historical .js URLs for a domain from web archives (gau +
    waybackurls), download and analyze them; merges into the project. Great for
    finding endpoints/secrets in JS that was removed from the live site."""
    return await _post("/api/archive", {"domain": domain, "use_gau": use_gau,
                                        "use_wayback": use_wayback, "subs": subs})


@mcp.tool()
async def job_status(job_id: str) -> dict:
    """Get status/progress of an analysis job."""
    return await _get(f"/api/jobs/{job_id}")


@mcp.tool()
async def list_endpoints(job_id: str, filter: str = "", exclude_static: bool = True,
                         limit: int = 100, offset: int = 0) -> dict:
    """List discovered endpoints. `filter` is a jsrecon expression, e.g.
    'category=api && has_param' or 'tag=idor || tag=redirect' or
    'domain=*kuper.ru && method=POST'. Static assets are hidden by default.
    Returns endpoints with idx, method, url, params, category and gf tags.
    """
    try:
        return await _get(f"/api/jobs/{job_id}/endpoints", filter=filter,
                          exclude_static=exclude_static, limit=limit, offset=offset)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 400:
            return {"error": f"bad filter: {e.response.text}. "
                    "Use search_endpoints() for structured matching instead."}
        raise


@mcp.tool()
async def get_endpoint(job_id: str, idx: int) -> dict:
    """Get full detail of one endpoint including the raw HTTP request. If a
    browser session is active, the request already carries the session cookies.
    """
    return await _get(f"/api/jobs/{job_id}/endpoint/{idx}", session_cookies=True)


@mcp.tool()
async def get_findings(job_id: str) -> dict:
    """Get SAST findings (secrets from jsluice) for a job."""
    return await _get(f"/api/jobs/{job_id}/findings")


@mcp.tool()
async def list_hosts(job_id: str) -> dict:
    """List hosts with counts of API/param-bearing endpoints."""
    return await _get(f"/api/jobs/{job_id}/hosts")


@mcp.tool()
async def get_openapi(job_id: str, host: str = "") -> dict:
    """Get an OpenAPI 3.0 spec (for Acunetix/Burp import) — one host or all."""
    return await _get(f"/api/jobs/{job_id}/openapi.json", host=host or None)


@mcp.tool()
async def session_status() -> dict:
    """Is the human-opened browser session active, and how many cookies it holds."""
    return await _get("/api/session/status")


@mcp.tool()
async def get_session_cookies(url: str = "") -> dict:
    """Read the CURRENT cookies from the live browser session (the 'cookie
    donor'). Call this whenever you want fresh cookies — e.g. after the human
    logs in or ServicePipe reissues them. Pass a URL to filter by domain.
    Returns a ready-to-use Cookie header plus the individual cookies.
    """
    return await _get("/api/session/cookies", url=url)


@mcp.tool()
async def send_request(job_id: str, idx: int, use_session: bool = True,
                       method: Optional[str] = None, url: Optional[str] = None,
                       body: Union[str, dict, list, None] = None,
                       cookies: Optional[str] = None,
                       headers: Optional[dict] = None,
                       timeout_ms: int = 20000) -> dict:
    """Replay endpoint #idx from a SPECIFIC job (per-job list). For the merged
    project use combined_send(); for an arbitrary from-scratch request use send().
    Rides the human session/live cookies with use_session=True (recommended
    behind ServicePipe). `body` accepts a string or a JSON object/array. Override
    method/url/body to fuzz. Nothing is sent until you call this."""
    payload: dict[str, Any] = {"use_session": use_session, "cookies": cookies,
                               "timeout_ms": timeout_ms}
    if headers:
        payload["headers"] = headers
    if method:
        payload["override_method"] = method
    if url:
        payload["override_url"] = url
    if body is not None:
        payload["override_body"] = body
    return await _post(f"/api/jobs/{job_id}/replay/{idx}", payload)


@mcp.tool()
async def combined_endpoints(filter: str = "", exclude_static: bool = True,
                             limit: int = 100, offset: int = 0) -> dict:
    """List the MERGED, de-duplicated endpoints across all Burp + katana jobs
    (the working project). `filter` is the DSL (e.g. 'category=api && has_param').
    For plain structured lookups prefer search_endpoints() — it can't 400 on a
    malformed expression. Paginated server-side via limit/offset; the project can
    hold 1000+ endpoints so ALWAYS page rather than pulling everything.
    """
    try:
        data = await _get("/api/combined/endpoints", filter=filter,
                          exclude_static=exclude_static, limit=limit, offset=offset)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 400:
            return {"error": f"bad filter: {e.response.text}. "
                    "Use search_endpoints() for structured matching instead."}
        raise
    return data


@mcp.tool()
async def search_endpoints(domain: str = "", path_contains: str = "", method: str = "",
                           has_param: Optional[bool] = None, tag: str = "",
                           category: str = "", exclude_static: bool = True,
                           limit: int = 100, offset: int = 0) -> dict:
    """Structured search over the merged project — NO filter DSL, so it never
    400s. All fields AND-combine (case-insensitive): `domain` substring of host,
    `path_contains` substring of path/url, `method` exact, `category` exact
    (api/page/static), `tag` a gf tag, `has_param` true/false. Prefer this over
    combined_endpoints(filter=...) for reliable lookups on a large project.
    """
    return await _get("/api/combined/search", domain=domain,
                      path_contains=path_contains, method=method,
                      has_param=has_param, tag=tag, category=category,
                      exclude_static=exclude_static, limit=limit, offset=offset)


@mcp.tool()
async def combined_endpoint(idx: int) -> dict:
    """Full detail + raw HTTP request for one merged endpoint (session cookies
    injected if a browser session is active)."""
    return await _get(f"/api/combined/endpoint/{idx}")


@mcp.tool()
async def combined_findings() -> dict:
    """SAST findings (secrets) across the whole merged project."""
    return await _get("/api/combined/findings")


@mcp.tool()
async def combined_openapi(host: str = "") -> dict:
    """OpenAPI 3.0 spec built from the merged project (for Acunetix/Burp)."""
    return await _get("/api/combined/openapi.json", host=host or None)


@mcp.tool()
async def combined_send(idx: int, use_session: bool = True,
                        method: Optional[str] = None, url: Optional[str] = None,
                        body: Union[str, dict, list, None] = None,
                        cookies: Optional[str] = None,
                        headers: Optional[dict] = None,
                        timeout_ms: int = 20000) -> dict:
    """Replay a MERGED-project endpoint by its idx (from combined_endpoints /
    search_endpoints), with optional overrides. Use send() instead when you want
    a request not tied to a discovered endpoint. `body` accepts a string or a
    JSON object/array (auto-encoded). Persistent set_auth() headers apply.
    Nothing is sent until you call this."""
    payload: dict[str, Any] = {"use_session": use_session, "cookies": cookies,
                               "timeout_ms": timeout_ms}
    if headers:
        payload["headers"] = headers
    if method:
        payload["override_method"] = method
    if url:
        payload["override_url"] = url
    if body is not None:
        payload["override_body"] = body
    return await _post(f"/api/combined/replay/{idx}", payload)


@mcp.tool()
async def send(url: str, method: str = "GET", headers: Optional[dict] = None,
               body: Union[str, dict, list, None] = None,
               cookies: Optional[str] = None, use_session: bool = True,
               timeout_ms: int = 20000) -> dict:
    """Send a FULLY hand-crafted HTTP request from scratch (no endpoint needed).
    This is THE free-form fuzzing primitive — use it whenever you want to craft
    an arbitrary request. (send_request/combined_send are only for replaying a
    DISCOVERED endpoint by its idx with small overrides.)

    `body` may be a raw string OR a JSON object/array — a dict/list is
    auto-encoded to a JSON string and Content-Type: application/json is set
    unless you pass your own. Persistent auth headers set via set_auth() are
    applied automatically. `timeout_ms` bounds the request (raise it for slow
    endpoints). Routes through the in-browser agent (bypasses ServicePipe) when
    one is alive for the origin, else the Playwright browser. Returns status,
    headers, body."""
    return await _post("/api/send", {
        "url": url, "method": method, "headers": headers or {},
        "body": body, "cookies": cookies, "use_session": use_session,
        "timeout_ms": timeout_ms,
    })


@mcp.tool()
async def get_storage(origin: str = "") -> dict:
    """Read localStorage/sessionStorage the in-browser agent captured for an
    origin (or all origins if empty). Surfaces Bearer/JWT/token-like values
    (`tokens[]`) that the SPA keeps client-side — NOT in cookies — so you can
    feed one to set_auth(authorization="Bearer <token>"). Use this when an API
    returns 401 and the auth token lives in web storage rather than a cookie."""
    return await _get("/api/storage", origin=origin)


@mcp.tool()
async def set_auth(authorization: str = "", headers: Optional[dict] = None,
                   clear: bool = False) -> dict:
    """Set auth header(s) applied automatically to EVERY subsequent send/replay
    for this project — so you don't repeat them each request. Pass
    `authorization` as a shortcut for the Authorization header (e.g.
    'Bearer eyJ...'), or `headers` for arbitrary ones (e.g. {"X-Api-Key":"..."}).
    `clear=True` wipes them. An explicit header on a specific send still wins."""
    h = dict(headers or {})
    if authorization:
        h["Authorization"] = authorization
    return await _post("/api/settings/auth", {"headers": h, "clear": clear})


@mcp.tool()
async def stop_job(job_id: str) -> dict:
    """Stop a running job (e.g. a katana crawl)."""
    return await _post(f"/api/jobs/{job_id}/stop", {})


@mcp.tool()
async def save_project() -> dict:
    """Persist the current merged project (overwrites the single saved project)."""
    return await _post("/api/project/save", {})


@mcp.tool()
async def clear_project(delete_saved: bool = False) -> dict:
    """Empty the working project (all merged endpoints/findings). With
    delete_saved=True also deletes the persisted file so it won't reload on next
    login. Use to start a fresh target."""
    return await _post("/api/project/clear", {"delete_saved": delete_saved})


@mcp.tool()
async def set_proxy(server: str = "") -> dict:
    """Set an http/socks5 proxy for browser traffic (e.g. socks5://127.0.0.1:1080).
    Empty string disables it. Restart the browser session to apply to it."""
    return await _post("/api/settings/proxy", {"server": server})


def main():
    mcp.run()


if __name__ == "__main__":
    main()
