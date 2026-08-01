"""Burp-style intercepting proxy for passing ServicePipe / anti-bot.

Instead of driving a browser over CDP (which anti-bots detect), we run mitmdump
as a SEPARATE process and launch a PLAIN Chromium pointed at it — a normal,
un-instrumented browser, exactly like Burp's embedded browser. The human solves
the challenge once; a mitmdump addon harvests the LIVE Cookie + User-Agent from
the proxied traffic into a JSON file (so rotating cookies stay fresh). Replay
then rides Chrome's network stack with the freshest harvested cookie/UA.

mitmdump runs out-of-process on purpose: mitmproxy calls sys.exit on fatal
errors, which would kill the FastAPI server if run in-process.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
from typing import Optional

CHROMIUM = os.environ.get("CHROMIUM_PATH", "/usr/bin/chromium")
MITMDUMP_BIN = os.environ.get("MITMDUMP_BIN", shutil.which("mitmdump") or "mitmdump")

# JS agent injected into target pages: polls jsrecon (via the sentinel host) and
# runs each queued request with fetch() FROM the real ServicePipe-passed browser.
SENTINEL_HOST = "jsrecon.proxy"
_AGENT_JS = r"""(function(){
  if (window.__jsrecon_agent__) return; window.__jsrecon_agent__ = true;
  var BASE = "https://jsrecon.proxy", done = 0, badge = null;
  function log(m){ try{ console.log("[jsrecon-agent]", m); }catch(e){} }
  function setBadge(txt, color){
    try{
      if(!badge){
        badge = document.createElement("div");
        badge.style.cssText = "position:fixed;z-index:2147483647;bottom:10px;right:10px;"+
          "background:#111;color:#0f0;font:12px/1.4 monospace;padding:6px 10px;"+
          "border:1px solid #0a0;border-radius:6px;opacity:.92;pointer-events:none";
        (document.body||document.documentElement).appendChild(badge);
      }
      badge.textContent = "[jsrecon] " + txt;
      badge.style.color = color || "#0f0";
      badge.style.borderColor = color || "#0a0";
    }catch(e){}
  }
  var lastStore = "";
  function dumpStore(store){
    var o = {};
    try{ for (var i=0;i<store.length;i++){ var k=store.key(i); var v=store.getItem(k);
      if (v!=null) o[k] = (v.length>8192 ? v.slice(0,8192) : v); } }catch(e){}
    return o;
  }
  async function sendStore(){
    try{
      var payload = {origin: location.origin, ls: dumpStore(window.localStorage||{}),
                     ss: dumpStore(window.sessionStorage||{})};
      var s = JSON.stringify(payload);
      if (s === lastStore) return;
      lastStore = s;
      await fetch(BASE+"/storage", {method:"POST", headers:{"Content-Type":"application/json"}, body:s});
    }catch(e){}
  }
  var WORKERS = 8;               // concurrent in-flight requests per tab
  function sleep(ms){ return new Promise(function(res){ setTimeout(res, ms); }); }
  async function runJob(job){
    var out;
    try{
      var jh = job.headers||{}; jh["X-Jsrecon-Agent"] = "1";
      var opt = {method: job.method||"GET", headers: jh, credentials:"include"};
      if (job.body) opt.body = job.body;
      var resp = await fetch(job.url, opt);
      var text = await resp.text();
      var hdrs = {}; resp.headers.forEach(function(v,k){hdrs[k]=v;});
      out = {id: job.id, ok:true, status: resp.status, statusText: resp.statusText||"",
             headers: hdrs, body: text.slice(0,300000), length: text.length};
    }catch(e){ out = {id: job.id, ok:false, error: String(e)}; log("exec error "+e); }
    done++;
    await fetch(BASE+"/exec/result", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(out)});
  }
  async function worker(){
    while(true){
      try{
        var r = await fetch(BASE+"/exec/next?origin="+encodeURIComponent(location.origin), {cache:"no-store"});
        var job = await r.json();
        if (job && job.id){
          setBadge("running x"+WORKERS+" done "+done, "#ff0");
          await runJob(job);
          continue;
        }
        setBadge("agent active x"+WORKERS+" done "+done, "#0f0");
      }catch(e){
        setBadge("no proxy link: "+e, "#f60");
      }
      await sleep(700);          // only when the queue is empty
    }
  }
  async function storeLoop(){ while(true){ sendStore(); await sleep(2000); } }
  log("started on "+location.origin);
  setBadge("connecting...", "#ff0");
  for (var w=0; w<WORKERS; w++) worker();
  storeLoop();
})();"""

# mitmdump addon (runs in the mitmdump process): (1) harvest Cookie+UA per host,
# (2) inject the agent into HTML pages, (3) bridge the sentinel host <-> jsrecon.
_ADDON_TEMPLATE = r'''
import json, os, re, threading, urllib.request
from mitmproxy import http

_META_CSP = re.compile(r'<meta[^>]+http-equiv=["\']?content-security-policy["\']?[^>]*>', re.I)

OUT = os.environ["JSRECON_COOKIE_FILE"]
PIN_FILE = os.environ.get("JSRECON_PIN_FILE", "")
JSRECON = os.environ.get("JSRECON_URL", "http://127.0.0.1:8777")
TOKEN = os.environ.get("JSRECON_TOKEN", "")
SENTINEL = "jsrecon.proxy"
AGENT_JS = __AGENT_JS__
CORS = {"Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"}
_lock = threading.Lock()
_data = {}

# pinned hosts: for these, a redirect response is replaced by a 200 HTML stub
# carrying the agent, so the browser tab STAYS on that origin (and hosts a
# same-origin agent) instead of following the redirect away.
_pins = {"list": [], "mtime": -1.0}

def _pinned(host):
    if not PIN_FILE:
        return False
    try:
        m = os.path.getmtime(PIN_FILE)
        if m != _pins["mtime"]:
            with open(PIN_FILE) as f:
                _pins["list"] = json.load(f)
            _pins["mtime"] = m
    except Exception:
        pass
    host = (host or "").lower()
    for p in _pins["list"]:
        p = p.lower()
        if host == p or host.endswith("." + p):
            return True
    return False

def _pin_stub(host, location):
    body = (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>jsrecon pinned</title></head>"
        "<body style=\"font:14px/1.6 monospace;background:#0d0d0d;color:#0f0;padding:22px\">"
        "<b>[jsrecon]</b> agent PINNED to <b>" + host + "</b><br>"
        "redirect suppressed -> <span style=\"color:#888\">" + (location or "?") + "</span><br>"
        "this tab now hosts a same-origin agent for this domain. leave it open.<br>"
        "<script>" + AGENT_JS + "</script></body></html>"
    )
    return body.encode("utf-8", "replace")

# bypass any HTTP_PROXY/ALL_PROXY env — the callback to jsrecon is direct localhost
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def _api(path, method="GET", payload=None):
    req = urllib.request.Request(
        JSRECON + path, method=method,
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
        data=json.dumps(payload).encode() if payload is not None else None)
    try:
        with _OPENER.open(req, timeout=70) as r:
            return r.read()
    except Exception:
        return b"{}"

def request(flow):
    h = flow.request.headers
    ck = h.get("cookie", ""); ua = h.get("user-agent", "")
    if ck or ua:
        with _lock:
            d = _data.setdefault(flow.request.host, {})
            if ck: d["cookie"] = ck
            if ua: d["ua"] = ua
            try:
                tmp = OUT + ".tmp"
                with open(tmp, "w") as f: json.dump(_data, f)
                os.replace(tmp, OUT)
            except Exception: pass
    if flow.request.pretty_host == SENTINEL:
        if flow.request.method == "OPTIONS":
            flow.response = http.Response.make(204, b"", CORS); return
        p = flow.request.path
        if p.startswith("/exec/next"):
            flow.response = http.Response.make(200, _api("/api" + p),
                {"Content-Type": "application/json", **CORS}); return
        if p.startswith("/exec/result"):
            _api("/api/exec/result", "POST", json.loads(flow.request.get_text() or "{}"))
            flow.response = http.Response.make(200, b'{"ok":true}',
                {"Content-Type": "application/json", **CORS}); return
        if p.startswith("/storage"):
            _api("/api/exec/storage", "POST", json.loads(flow.request.get_text() or "{}"))
            flow.response = http.Response.make(200, b'{"ok":true}',
                {"Content-Type": "application/json", **CORS}); return
        flow.response = http.Response.make(404, b"", CORS)
        return

    # PINNED host: for a top-level navigation, serve the agent stub immediately
    # (no upstream fetch) so the tab lands and STAYS on this origin — the target's
    # redirect never happens and can't be served from browser cache. Sub-resource
    # and agent (x-jsrecon-agent) requests pass through to the real upstream.
    if _pinned(flow.request.pretty_host) and not flow.request.headers.get("x-jsrecon-agent"):
        dest = flow.request.headers.get("sec-fetch-dest", "")
        accept = flow.request.headers.get("accept", "")
        is_nav = (dest == "document"
                  or (dest == "" and flow.request.method == "GET" and "text/html" in accept))
        if is_nav:
            flow.response = http.Response.make(
                200, _pin_stub(flow.request.pretty_host, flow.request.pretty_url),
                {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"})
            return

def response(flow):
    if flow.request.pretty_host == SENTINEL:
        return
    # don't inject the agent into responses the agent itself fetched (keeps
    # replayed response bodies clean)
    if flow.request.headers.get("x-jsrecon-agent"):
        return
    ct = flow.response.headers.get("content-type", "")
    if "text/html" in ct and flow.response.content and b"__jsrecon_agent__" not in flow.response.content:
        try:
            # strip CSP so the injected inline agent isn't blocked (safe delete —
            # Headers.pop raises on a missing key in mitmproxy)
            for hdr in ("content-security-policy", "content-security-policy-report-only",
                        "x-webkit-csp"):
                if hdr in flow.response.headers:
                    del flow.response.headers[hdr]
            html = _META_CSP.sub("", flow.response.get_text())
            inj = "<script>" + AGENT_JS + "</script>"
            if "</body>" in html:
                html = html.replace("</body>", inj + "</body>", 1)
            elif "</head>" in html:
                html = html.replace("</head>", inj + "</head>", 1)
            else:
                html = html + inj
            flow.response.set_text(html)
        except Exception:
            pass
'''


class CookieStore:
    """Reads the mitmdump-harvested Cookie/UA JSON file (latest per host)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._cache: dict = {}
        self._mtime = -1.0

    def _load(self) -> dict:
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return self._cache
        if m != self._mtime:
            try:
                with open(self.path, encoding="utf-8") as f:
                    self._cache = json.load(f)
                self._mtime = m
            except Exception:
                pass
        return self._cache

    def _match(self, host: str) -> dict:
        data = self._load()
        if host in data:
            return data[host]
        for h, d in data.items():
            if host.endswith("." + h) or h.endswith("." + host) or host.endswith(h):
                return d
        return {}

    def cookie_for(self, host: str) -> str:
        return self._match(host).get("cookie", "")

    def ua_for(self, host: str) -> str:
        return self._match(host).get("ua", "")

    def total(self) -> int:
        return sum(1 for d in self._load().values() if d.get("cookie"))


class MitmProxy:
    def __init__(self, port: int = 8899) -> None:
        self.port = port
        self.cookie_file = os.path.join(tempfile.gettempdir(), "jsrecon_cookies.json")
        self.addon_file = os.path.join(tempfile.gettempdir(), "jsrecon_mitm_addon.py")
        self.pin_file = os.path.join(tempfile.gettempdir(), "jsrecon_pins.json")
        self.ca_dir = os.path.expanduser("~/.mitmproxy")
        self.store = CookieStore(self.cookie_file)
        self.jsrecon_url = "http://127.0.0.1:8777"   # set by server (agent callback)
        self.token = ""
        self._pins: list[str] = []
        self._proc: Optional[subprocess.Popen] = None
        self._browser_proc: Optional[subprocess.Popen] = None
        self._url = ""

    def _write_pins(self) -> None:
        try:
            tmp = self.pin_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._pins, f)
            os.replace(tmp, self.pin_file)
        except Exception:
            pass

    def add_pin(self, host: str) -> list[str]:
        host = (host or "").strip().lower().lstrip(".")
        if host and host not in self._pins:
            self._pins.append(host)
            self._write_pins()
        return self._pins

    def remove_pin(self, host: str) -> list[str]:
        host = (host or "").strip().lower().lstrip(".")
        self._pins = [p for p in self._pins if p != host]
        self._write_pins()
        return self._pins

    def pins(self) -> list[str]:
        return list(self._pins)

    def active(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    async def start(self) -> None:
        if self.active():
            return
        # clean up any orphan mitmdump from a previous run (frees the port)
        try:
            subprocess.run(["pkill", "-f", self.addon_file],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await asyncio.sleep(0.4)
        except Exception:
            pass
        addon = _ADDON_TEMPLATE.replace("__AGENT_JS__", json.dumps(_AGENT_JS))
        with open(self.addon_file, "w", encoding="utf-8") as f:
            f.write(addon)
        try:
            if os.path.exists(self.cookie_file):
                os.remove(self.cookie_file)
        except OSError:
            pass
        self._write_pins()   # ensure the pin file exists for the addon
        env = {**os.environ, "JSRECON_COOKIE_FILE": self.cookie_file,
               "JSRECON_PIN_FILE": self.pin_file,
               "JSRECON_URL": self.jsrecon_url, "JSRECON_TOKEN": self.token}
        self._proc = subprocess.Popen(
            [MITMDUMP_BIN, "-s", self.addon_file, "--listen-host", "127.0.0.1",
             "-p", str(self.port), "--ssl-insecure", "-q",
             # generate MITM certs from SNI without connecting upstream — lets us
             # MITM the fake sentinel host (jsrecon.proxy) over HTTPS
             "--set", "upstream_cert=false",
             "--set", "connection_strategy=lazy"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(1.8)  # let it bind + generate the CA

    def launch_browser(self, url: str = "") -> bool:
        """Launch a plain (non-automated) Chromium through the proxy. Returns
        False if the browser could not be started (e.g. no display)."""
        profile = os.path.join(tempfile.gettempdir(), "jsrecon_proxy_profile")
        os.makedirs(profile, exist_ok=True)
        args = [
            CHROMIUM,
            f"--proxy-server=http://127.0.0.1:{self.port}",
            "--ignore-certificate-errors",
            f"--user-data-dir={profile}",   # REQUIRED for --disable-web-security to take effect
            "--no-first-run", "--no-default-browser-check",
            # kill same-origin policy so the injected agent can read cross-origin
            # responses (e.g. web.kuper.ru's agent fetching api.kuper.ru). The
            # site-isolation disable is needed or fetch CORS still gets enforced.
            "--disable-web-security",
            "--disable-features=IsolateOrigins,site-per-process",
            # keep the disk cache tiny so cacheable 3xx redirects aren't served
            # from cache (which would bypass the proxy and defeat domain pinning)
            "--disk-cache-size=1",
        ]
        if os.environ.get("JSRECON_NO_SANDBOX") == "1":
            args.append("--no-sandbox")
        if url:
            args.append(url)
        self._url = url
        try:
            self._browser_proc = subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    def status(self) -> dict:
        return {
            "active": self.active(),
            "port": self.port,
            "url": self._url,
            "hosts_with_cookies": self.store.total() if self.active() else 0,
            "ca_cert": os.path.join(self.ca_dir, "mitmproxy-ca-cert.pem"),
            "browser_running": self._browser_proc is not None
            and self._browser_proc.poll() is None,
            "pins": list(self._pins),
        }

    async def stop(self) -> dict:
        for p in (self._browser_proc, self._proc):
            if p is not None:
                try:
                    p.terminate()
                except Exception:
                    pass
        self._browser_proc = None
        self._proc = None
        return {"active": False}
