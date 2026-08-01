"""Collect JS files for a domain with katana, then feed the same pipeline.

katana crawls the target (optionally headless, optionally with the browser
session's cookies to get past ServicePipe/auth), emits .js URLs; we download
them (through the browser session when asked) into JsFile objects that go
through the exact same jsluice/secrets analysis as Burp-sourced JS.
"""
from __future__ import annotations

import asyncio
import os
import re
from typing import Callable, Optional

from .models import JsFile

# match real .js file URLs (avoid .json etc.)
_JS_URL_RE = re.compile(r"\.m?js(\?|#|$)", re.IGNORECASE)


class RateLimiter:
    """Global requests-per-second throttle for self-downloading tools.
    rps <= 0 means unlimited (no pacing). Paces the *start* of each request so
    concurrent workers never exceed `rps` new requests per second combined."""

    def __init__(self, rps: float = 0):
        self.interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self):
        if self.interval <= 0:
            return
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            start = self._next if self._next > now else now
            self._next = start + self.interval
            delay = start - now
        if delay > 0:
            await asyncio.sleep(delay)

KATANA_BIN = os.environ.get("KATANA_BIN", os.path.expanduser("~/go/bin/katana"))
CHROMIUM = os.environ.get("CHROMIUM_PATH", "/usr/bin/chromium")


async def crawl_js(
    domain: str,
    depth: int = 2,
    headless: bool = False,
    cookie_header: str = "",
    proxy: str = "",
    duration_s: int = 0,
    max_pages: int = 0,
    max_rps: float = 0,
    progress: Optional[Callable] = None,
    on_proc: Optional[Callable] = None,
) -> list[str]:
    """Run katana and return a de-duplicated list of discovered .js URLs.

    `on_proc(proc)` receives the subprocess so callers can stop it.
    """
    url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    # NB: -em js is intentionally NOT used — it interacts badly with katana's
    # default extension filter and suppresses output. We filter .js ourselves.
    cmd = [KATANA_BIN, "-u", url, "-jc", "-silent", "-nc", "-d", str(depth)]
    if headless:
        cmd += ["-headless", "-system-chrome-path", CHROMIUM]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]
    if proxy:
        cmd += ["-proxy", proxy]
    if max_rps and max_rps > 0:
        cmd += ["-rate-limit", str(int(max_rps) or 1)]   # katana requests/sec cap
    if duration_s:
        cmd += ["-ct", f"{duration_s}s"]
    if max_pages:
        cmd += ["-mdp", str(max_pages)]

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    if on_proc:
        on_proc(proc)
    seen: list[str] = []
    seen_set: set[str] = set()
    assert proc.stdout
    async for line in proc.stdout:
        u = line.decode("utf-8", "replace").strip()
        if u and u not in seen_set and _JS_URL_RE.search(u):
            seen_set.add(u)
            seen.append(u)
            if progress:
                progress("crawl", len(seen))
    await proc.wait()
    return seen


async def fetch_js_files(
    urls: list[str],
    browser,
    use_session: bool = True,
    concurrency: int = 6,
    progress: Optional[Callable] = None,
    max_rps: float = 0,
    proxy: str = "",
) -> list[JsFile]:
    """Download each JS URL. Uses the human browser session only when it's needed
    and active (ServicePipe/auth); otherwise a fast concurrent httpx path — the
    difference matters a lot for archives, which can return hundreds of URLs.

    max_rps caps the combined request rate across all workers (0 = unlimited)."""
    out: list[JsFile] = []
    done = 0
    total = len(urls)
    limiter = RateLimiter(max_rps)

    # fast path: plain httpx when no live session is required
    if not (use_session and getattr(browser, "has_session", lambda: False)()):
        import httpx
        # when rate-limited, high concurrency is pointless; keep it modest
        sem = asyncio.Semaphore(20 if max_rps <= 0 else max(1, min(20, int(max_rps) + 1)))

        async def one_http(u: str, client):
            nonlocal done
            async with sem:
                await limiter.wait()
                try:
                    r = await client.get(u)
                    body = r.text if r.status_code == 200 else None
                except Exception:
                    body = None
            done += 1
            if progress and done % 25 == 0:
                progress("download", done)
            if body:
                out.append(JsFile(url=u, source=body, origin="katana", host=""))

        client_kw = dict(timeout=25, verify=False, follow_redirects=True)
        if proxy:
            client_kw["proxy"] = proxy   # route downloads through upstream proxy/VPN
        async with httpx.AsyncClient(**client_kw) as c:
            await asyncio.gather(*(one_http(u, c) for u in urls), return_exceptions=True)
        return out

    # session path: ride the human-solved browser session
    sem = asyncio.Semaphore(concurrency)

    async def one(u: str):
        nonlocal done
        async with sem:
            await limiter.wait()
            r = await browser.send("GET", u, use_session=use_session, timeout_ms=25000)
        done += 1
        if progress and done % 25 == 0:
            progress("download", done)
        if r.get("ok") and r.get("body"):
            out.append(JsFile(url=u, source=r["body"], origin="katana", host=""))

    await asyncio.gather(*(one(u) for u in urls), return_exceptions=True)
    return out


async def download_to_disk(
    urls: list[str],
    browser,
    writer,
    use_session: bool = True,
    concurrency: int = 6,
    progress: Optional[Callable] = None,
    max_rps: float = 0,
    proxy: str = "",
    should_stop: Optional[Callable] = None,
) -> int:
    """Download each URL and write it STRAIGHT to disk via `writer.add(url, body)`.
    Nothing is accumulated in memory — this is the streaming path used for large
    corpora so downloading 15k files does not OOM. Returns the count saved.

    `should_stop()` is polled per task so a user 'stop' aborts promptly: queued
    workers bail out immediately instead of finishing all 15k requests."""
    stop = should_stop or (lambda: False)
    limiter = RateLimiter(max_rps)
    done = ok = 0
    total = len(urls)

    if not (use_session and getattr(browser, "has_session", lambda: False)()):
        import httpx
        sem = asyncio.Semaphore(20 if max_rps <= 0 else max(1, min(20, int(max_rps) + 1)))

        async def one_http(u: str, client):
            nonlocal done, ok
            if stop():
                return
            async with sem:
                if stop():
                    return
                await limiter.wait()
                try:
                    r = await client.get(u)
                    body = r.text if r.status_code == 200 else None
                except Exception:
                    body = None
            done += 1
            if body:
                writer.add(u, body); ok += 1
            if progress and done % 50 == 0:
                progress("download", f"{done}/{total} ({ok} ok)")

        client_kw = dict(timeout=25, verify=False, follow_redirects=True)
        if proxy:
            client_kw["proxy"] = proxy
        async with httpx.AsyncClient(**client_kw) as c:
            await asyncio.gather(*(one_http(u, c) for u in urls), return_exceptions=True)
        return ok

    sem = asyncio.Semaphore(concurrency)

    async def one(u: str):
        nonlocal done, ok
        if stop():
            return
        async with sem:
            if stop():
                return
            await limiter.wait()
            r = await browser.send("GET", u, use_session=use_session, timeout_ms=25000)
        done += 1
        if r.get("ok") and r.get("body"):
            writer.add(u, r["body"]); ok += 1
        if progress and done % 50 == 0:
            progress("download", f"{done}/{total} ({ok} ok)")

    await asyncio.gather(*(one(u) for u in urls), return_exceptions=True)
    return ok
