"""Send requests through a real browser (Chromium via Playwright).

Two modes:

1. Ephemeral — a throwaway headless context per request (default).
2. Persistent session — a long-lived (optionally *headed*) browser with a
   user-data dir. A human opens the target once, solves the ServicePipe /
   anti-bot / captcha challenge, and every subsequent request rides that same
   context (cookies + browser TLS/network stack). This is what lets us push
   scanner/fuzzer traffic through protections that block plain HTTP clients.
"""
from __future__ import annotations

import os
import tempfile
from typing import Any, Optional
from .urlutil import safe_urlsplit as urlsplit

from playwright.async_api import async_playwright

from .http_build import build_body, build_query
from .models import Endpoint

_SYSTEM_CHROMIUM = os.environ.get("CHROMIUM_PATH", "/usr/bin/chromium")

# Injected before page scripts to hide the usual automation tells that
# ServicePipe / anti-bots fingerprint (navigator.webdriver, empty plugins,
# software WebGL, missing window.chrome, permissions quirk).
_STEALTH_JS = r"""
Object.defineProperty(navigator, 'webdriver', {get: () => false});
try { Object.defineProperty(navigator, 'languages', {get: () => ['ru-RU','ru','en-US','en']}); } catch(e){}
try { Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5].map(i => ({name:'Plugin'+i, filename:'p'+i}))}); } catch(e){}
window.chrome = window.chrome || { runtime: {}, app: {}, csi: function(){}, loadTimes: function(){} };
try {
  const q = window.navigator.permissions && window.navigator.permissions.query;
  if (q) window.navigator.permissions.query = (p) =>
    (p && p.name === 'notifications') ? Promise.resolve({state: Notification.permission}) : q(p);
} catch(e){}
(function(){
  const spoof = (proto) => {
    if (!proto) return;
    const gp = proto.getParameter;
    proto.getParameter = function(p){
      if (p === 37445) return 'Intel Inc.';                 // UNMASKED_VENDOR_WEBGL
      if (p === 37446) return 'Intel Iris OpenGL Engine';   // UNMASKED_RENDERER_WEBGL
      return gp.call(this, p);
    };
  };
  spoof(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype);
  spoof(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype);
})();
"""


def _parse_cookie_header(header: str, url: str):
    """Turn a raw `Cookie: a=1; b=2` header into Playwright cookie objects,
    scoped to the given URL's host (works cross-subdomain via a leading-dot domain)."""
    from .urlutil import safe_urlsplit as urlsplit
    host = urlsplit(url if "://" in url else "https://" + url).netloc.split(":")[0]
    # register cookies on the parent domain so they apply across subdomains
    parts = host.split(".")
    domain = "." + ".".join(parts[-2:]) if len(parts) >= 2 else host
    out = []
    for chunk in header.replace("Cookie:", "", 1).split(";"):
        chunk = chunk.strip()
        if "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        name = name.strip()
        if not name:
            continue
        out.append({"name": name, "value": value.strip(),
                    "domain": domain, "path": "/"})
    return out


class BrowserPool:
    def __init__(self, headless: bool = True) -> None:
        self.headless = headless
        self._pw = None
        self._browser = None
        self._proxy = ""            # e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080
        # real Chrome channel ("chrome"/"msedge") fixes UA + Sec-CH-UA branding
        self._channel = os.environ.get("JSRECON_BROWSER_CHANNEL", "")
        # persistent human-assisted session
        self._session_ctx = None
        self._session_page = None
        self._session_headed = False
        self._session_url = ""
        self._session_mode = ""     # "launch" | "cdp" | "manual"
        self._session_browser = None
        self._cookie_store = None   # proxy.CookieStore — live harvested cookies/UA
        self._user_data_dir = os.path.join(
            tempfile.gettempdir(), "jsrecon_profile"
        )

    def attach_cookie_store(self, store) -> None:
        """Attach the MITM-proxy cookie store so replay uses live rotating cookies."""
        self._cookie_store = store

    def set_proxy(self, server: str) -> None:
        """Set a proxy for browser traffic (http://.. or socks5://..). Empty = off.
        Applies to browsers launched afterwards (restart the session to apply)."""
        self._proxy = (server or "").strip()

    def _proxy_kw(self) -> dict:
        return {"proxy": {"server": self._proxy}} if self._proxy else {}

    def _launch_kw(self) -> dict:
        """Extra launch args. --disable-blink-features=AutomationControlled hides
        the automation flag; --no-sandbox only when running as root in a container
        (JSRECON_NO_SANDBOX=1)."""
        kw = dict(self._proxy_kw())
        args = ["--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process"]
        if os.environ.get("JSRECON_NO_SANDBOX") == "1":
            args += ["--no-sandbox", "--disable-dev-shm-usage"]
        kw["args"] = args
        if self._channel:
            kw["channel"] = self._channel
        return kw

    async def _ensure_pw(self):
        if self._pw is None:
            self._pw = await async_playwright().start()

    async def _ensure_browser(self):
        if self._browser is not None:
            return
        await self._ensure_pw()
        kw = {"headless": self.headless, **self._launch_kw()}
        try:
            self._browser = await self._pw.chromium.launch(**kw)
        except Exception:
            self._browser = await self._pw.chromium.launch(
                executable_path=_SYSTEM_CHROMIUM, **kw
            )

    # --------------------------- session control ---------------------------

    async def start_session(self, url: str = "", headed: bool = True,
                            cdp_url: str = "", channel: str = "",
                            stealth: bool = True) -> dict:
        """Start a human-assisted session.

        - cdp_url set -> ATTACH to a real Chrome the human launched with
          --remote-debugging-port (the cleanest bypass: a genuine browser, no
          webdriver/automation tells at all).
        - otherwise LAUNCH a persistent Chromium/Chrome with stealth patches and
          --disable-blink-features=AutomationControlled. `channel="chrome"` uses
          real Chrome (fixes UA + Sec-CH-UA branding).
        """
        await self._ensure_pw()
        if self._session_ctx is not None:
            await self.stop_session()
        if channel:
            self._channel = channel

        if cdp_url:
            # attach to the user's real running Chrome
            self._session_browser = await self._pw.chromium.connect_over_cdp(cdp_url)
            ctxs = self._session_browser.contexts
            self._session_ctx = ctxs[0] if ctxs else await self._session_browser.new_context()
            self._session_mode = "cdp"
            self._session_headed = True
        else:
            os.makedirs(self._user_data_dir, exist_ok=True)
            kwargs = dict(
                user_data_dir=self._user_data_dir,
                headless=not headed,
                ignore_https_errors=True,
                viewport={"width": 1366, "height": 850},
                locale="ru-RU",
                **self._launch_kw(),
            )
            try:
                self._session_ctx = await self._pw.chromium.launch_persistent_context(**kwargs)
            except Exception:
                # channel/chrome may be missing -> retry as plain system chromium
                kwargs.pop("channel", None)
                self._session_ctx = await self._pw.chromium.launch_persistent_context(
                    executable_path=_SYSTEM_CHROMIUM, **kwargs)
            self._session_mode = "launch"
            self._session_headed = headed

        if stealth:
            try:
                await self._session_ctx.add_init_script(_STEALTH_JS)
            except Exception:
                pass

        self._session_url = url
        if url:
            self._session_page = await self._session_ctx.new_page()
            try:
                await self._session_page.goto(url, wait_until="domcontentloaded", timeout=45000)
            except Exception:
                pass
        return await self.session_status()

    async def session_status(self) -> dict:
        active = self._session_ctx is not None
        cookies = []
        if active:
            try:
                cookies = await self._session_ctx.cookies()
            except Exception:
                cookies = []
        return {
            "active": active,
            "headed": self._session_headed,
            "url": self._session_url,
            "cookies": len(cookies),
            "mode": self._session_mode,          # "launch" | "cdp"
            "channel": self._channel or "chromium",
        }

    def has_session(self) -> bool:
        return self._session_ctx is not None

    async def set_manual_cookies(self, url: str, cookie_header: str,
                                 headed: bool = False) -> dict:
        """Inject cookies harvested from YOUR working browser (Burp/Chrome) into a
        browser context. Requests then ride Chrome's network stack (matching
        TLS/UA) with valid cookies — no captcha, because Playwright never touches
        the challenge page. This is the reliable way past ServicePipe.
        """
        await self._ensure_pw()
        if self._session_ctx is None or self._session_mode == "cdp":
            if self._session_ctx is not None:
                await self.stop_session()
            os.makedirs(self._user_data_dir, exist_ok=True)
            kwargs = dict(user_data_dir=self._user_data_dir, headless=not headed,
                          ignore_https_errors=True, **self._launch_kw())
            try:
                self._session_ctx = await self._pw.chromium.launch_persistent_context(**kwargs)
            except Exception:
                kwargs.pop("channel", None)
                self._session_ctx = await self._pw.chromium.launch_persistent_context(
                    executable_path=_SYSTEM_CHROMIUM, **kwargs)
            self._session_mode = "manual"
            self._session_headed = headed
        cookies = _parse_cookie_header(cookie_header, url)
        if cookies:
            try:
                await self._session_ctx.add_cookies(cookies)
            except Exception as e:  # noqa: BLE001
                return {"active": True, "added": 0, "error": str(e)}
        self._session_url = url
        st = await self.session_status()
        st["added"] = len(cookies)
        return st

    async def get_cookies(self, url: str = "") -> dict:
        """Harvest cookies the human/browser accumulated in the live session.

        Used as a 'cookie donor': the human logs in / passes ServicePipe in the
        headed window, and we read the resulting cookies to build (but not
        auto-send) authenticated requests. Pass a URL to filter by domain/path.
        """
        # prefer live proxy-harvested cookies (rotating ServicePipe)
        if self._cookie_store is not None and url:
            host = urlsplit(url).netloc.split(":")[0]
            live = self._cookie_store.cookie_for(host)
            if live:
                return {"active": True, "count": live.count(";") + 1,
                        "header": live, "cookies": [], "source": "proxy"}
        if self._session_ctx is None:
            return {"active": False, "count": 0, "cookies": [], "header": ""}
        try:
            raw = await self._session_ctx.cookies(url) if url else await self._session_ctx.cookies()
        except Exception:
            raw = []
        header = "; ".join(f"{c['name']}={c['value']}" for c in raw)
        return {
            "active": True, "count": len(raw), "header": header,
            "cookies": [
                {"name": c.get("name"), "value": c.get("value"),
                 "domain": c.get("domain"), "path": c.get("path"),
                 "secure": c.get("secure"), "httpOnly": c.get("httpOnly")}
                for c in raw
            ],
        }

    async def stop_session(self) -> dict:
        if self._session_mode == "cdp":
            # attached to the user's own Chrome — just disconnect, don't kill it
            if self._session_browser is not None:
                try:
                    await self._session_browser.close()
                except Exception:
                    pass
        elif self._session_ctx is not None:
            try:
                await self._session_ctx.close()
            except Exception:
                pass
        self._session_ctx = None
        self._session_page = None
        self._session_browser = None
        self._session_headed = False
        self._session_mode = ""
        return {"active": False}

    async def close(self) -> None:
        await self.stop_session()
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._pw:
            await self._pw.stop()
            self._pw = None

    # ------------------------------ sending ------------------------------

    async def send(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
        cookies: Optional[str] = None,
        timeout_ms: int = 20000,
        ignore_https_errors: bool = True,
        use_session: bool = True,
    ) -> dict[str, Any]:
        extra = dict(headers or {})
        if cookies:
            extra["Cookie"] = cookies
        # inject the freshest cookie + UA harvested by the MITM proxy (rotating
        # ServicePipe cookies) unless an explicit cookie was given
        if self._cookie_store is not None and not cookies:
            host = urlsplit(url).netloc.split(":")[0]
            live = self._cookie_store.cookie_for(host)
            if live:
                extra["Cookie"] = live
            ua = self._cookie_store.ua_for(host)
            if ua:
                extra["User-Agent"] = ua
        # make the request look like a real in-page XHR (ServicePipe checks these)
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        for k, v in {
            "Origin": origin, "Referer": origin + "/",
            "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
        }.items():
            extra.setdefault(k, v)
        for h in ("Host", "Content-Length", "Connection"):
            extra.pop(h, None)
            extra.pop(h.lower(), None)

        # Prefer the human-solved persistent session if present.
        if use_session and self._session_ctx is not None:
            api = self._session_ctx.request
            close_ctx = None
        else:
            await self._ensure_browser()
            ctx = await self._browser.new_context(
                ignore_https_errors=ignore_https_errors, **self._proxy_kw())
            api = ctx.request
            close_ctx = ctx

        try:
            resp = await api.fetch(
                url, method=method, headers=extra,
                data=body if body else None,
                timeout=timeout_ms, max_redirects=0,
            )
            raw_body = await resp.body()
            text = raw_body.decode("utf-8", "replace")
            return {
                "ok": True, "status": resp.status, "status_text": resp.status_text,
                "url": resp.url, "headers": dict(resp.headers),
                "body": text[:200_000], "length": len(raw_body),
                "via_session": use_session and close_ctx is None,
            }
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}
        finally:
            if close_ctx is not None:
                await close_ctx.close()

    async def send_endpoint(self, ep: Endpoint, cookies: Optional[str] = None, **kw) -> dict[str, Any]:
        query = build_query(ep)
        url = ep.url.split("?")[0]
        if query:
            url = f"{url}?{query}"
        body, ctype = build_body(ep)
        headers = dict(ep.headers)
        if body and "Content-Type" not in headers:
            headers["Content-Type"] = ctype
        return await self.send(ep.method, url, headers, body, cookies=cookies, **kw)
