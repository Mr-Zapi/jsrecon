"""Collect historical JS URLs for a domain from web archives (gau + waybackurls).

Archives surface JS that's been removed from the live site but whose old
endpoints/secrets may still work — high-value recon. We gather URLs, keep only
.js, dedupe; downloading + analysis is done by the shared job pipeline (same as
katana), so archive JS goes through webpack/source maps/jsluice/gf/SAST too.
"""
from __future__ import annotations

import asyncio
import os
from typing import Callable, Optional

from .katana import _JS_URL_RE

GAU_BIN = os.environ.get("GAU_BIN", os.path.expanduser("~/go/bin/gau"))
WAYBACK_BIN = os.environ.get("WAYBACKURLS_BIN", os.path.expanduser("~/go/bin/waybackurls"))


async def _run(cmd: list[str], stdin_data: Optional[bytes], timeout: int,
               seen: set, out: list, progress: Optional[Callable],
               env: Optional[dict] = None):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.PIPE if stdin_data else None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )
    except FileNotFoundError:
        return
    if stdin_data and proc.stdin:
        proc.stdin.write(stdin_data)
        proc.stdin.close()
    assert proc.stdout
    try:
        while True:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
            if not line:
                break
            u = line.decode("utf-8", "replace").strip()
            if u and u not in seen and _JS_URL_RE.search(u):
                seen.add(u)
                out.append(u)
                if progress and len(out) % 25 == 0:
                    progress("archive", len(out))
    except asyncio.TimeoutError:
        pass
    finally:
        try:
            proc.kill()
        except Exception:
            pass


async def gather_js_urls(
    domain: str,
    use_gau: bool = True,
    use_wayback: bool = True,
    subs: bool = True,
    proxy: str = "",
    timeout: int = 120,
    progress: Optional[Callable] = None,
) -> list[str]:
    """Return a de-duplicated list of .js URLs for the domain from the archives."""
    host = domain.replace("https://", "").replace("http://", "").strip("/").split("/")[0]
    seen: set[str] = set()
    out: list[str] = []
    tasks = []

    if use_wayback:
        # waybackurls has no --proxy flag but honours HTTP(S)_PROXY env
        wb_env = None
        if proxy:
            wb_env = {**os.environ, "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy}
        tasks.append(_run([WAYBACK_BIN], f"{host}\n".encode(), timeout, seen, out,
                          progress, env=wb_env))
    if use_gau:
        cmd = [GAU_BIN, "--threads", "5"]
        if subs:
            cmd.append("--subs")
        if proxy:
            cmd += ["--proxy", proxy]
        cmd.append(host)
        tasks.append(_run(cmd, None, timeout, seen, out, progress))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    return out
