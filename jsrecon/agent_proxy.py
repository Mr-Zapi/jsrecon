"""Tool-facing HTTP/HTTPS proxy that routes every request through the browser
agent — so external tools (dirsearch, ffuf, nuclei, katana, curl…) can bypass
ServicePipe by pointing `--proxy http://127.0.0.1:8888` at us.

Implementation: a SECOND mitmdump instance (separate from the cookie-harvesting
one). We do NOT hand-roll TLS — mitmproxy terminates TLS with its own CA, then
its addon, instead of forwarding upstream, calls jsrecon /api/send which runs the
request inside the real ServicePipe-passed browser (via the injected agent) and
returns the response.

The external tool must trust mitmproxy's CA (~/.mitmproxy/mitmproxy-ca-cert.pem)
or run insecure (curl -k, dirsearch is insecure by default, ffuf -k, nuclei -...).

Limitation: bodies come back as text (fetch() API) so binary responses are
mangled. For recon (HTML/JSON/JS) this is fine.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile
from typing import Optional

MITMDUMP_BIN = os.environ.get("MITMDUMP_BIN", shutil.which("mitmdump") or "mitmdump")

# Addon that runs INSIDE the tool-facing mitmdump: every request is handed to
# jsrecon /api/send (which dispatches to the browser agent) and the agent's
# response is returned to the tool. No upstream connection is made.
_ADDON_TEMPLATE = r'''
import json, os, urllib.request
from mitmproxy import http

JSRECON = os.environ.get("JSRECON_URL", "http://127.0.0.1:8777")
TOKEN = os.environ.get("JSRECON_TOKEN", "")

# bypass any HTTP_PROXY/ALL_PROXY env — the callback to jsrecon is direct localhost
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# headers we must NOT copy back verbatim (mitmproxy recomputes length; the body
# is already decoded text so stale encoding/length would corrupt the response)
_SKIP_RESP = {"content-length", "content-encoding", "transfer-encoding",
              "connection", "keep-alive"}
_SKIP_REQ = {"proxy-connection", "proxy-authorization", "connection",
             "keep-alive", "content-length", "host"}

def _api(path, payload):
    req = urllib.request.Request(
        JSRECON + path, method="POST",
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
        data=json.dumps(payload).encode())
    with _OPENER.open(req, timeout=90) as r:
        return r.read()

def request(flow):
    try:
        body = flow.request.get_text(strict=False)
    except Exception:
        body = None
    hdrs = {k: v for k, v in flow.request.headers.items()
            if k.lower() not in _SKIP_REQ}
    payload = {"method": flow.request.method, "url": flow.request.pretty_url,
               "headers": hdrs, "body": body or None, "use_session": True}
    try:
        d = json.loads(_api("/api/send", payload))
    except Exception as e:
        flow.response = http.Response.make(
            502, ("jsrecon agent-proxy error: " + str(e)).encode(),
            {"Content-Type": "text/plain"})
        return
    if not d.get("ok", True) and d.get("error"):
        flow.response = http.Response.make(
            502, ("agent error: " + str(d.get("error"))).encode(),
            {"Content-Type": "text/plain"})
        return
    status = int(d.get("status") or 502) or 502
    rbody = (d.get("body") or "").encode("utf-8", "replace")
    rhdrs = {k: v for k, v in (d.get("headers") or {}).items()
             if k.lower() not in _SKIP_RESP}
    rhdrs.setdefault("X-Jsrecon-Via", "agent")
    flow.response = http.Response.make(status, rbody, rhdrs)
'''


class AgentProxy:
    """Launches a dedicated mitmdump that routes all traffic through the agent."""

    def __init__(self, port: int = 8888) -> None:
        self.port = port
        self.addon_file = os.path.join(tempfile.gettempdir(), "jsrecon_agentproxy_addon.py")
        self.jsrecon_url = os.environ.get("JSRECON_URL", "http://127.0.0.1:8777")
        self.token = ""
        self._proc: Optional[subprocess.Popen] = None

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    async def start(self) -> None:
        if self.running():
            return
        # kill any orphan from a previous run (frees the port)
        try:
            subprocess.run(["pkill", "-f", self.addon_file],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await asyncio.sleep(0.3)
        except Exception:
            pass
        with open(self.addon_file, "w", encoding="utf-8") as f:
            f.write(_ADDON_TEMPLATE)
        env = {**os.environ, "JSRECON_URL": self.jsrecon_url,
               "JSRECON_TOKEN": self.token}
        self._proc = subprocess.Popen(
            [MITMDUMP_BIN, "-s", self.addon_file, "--listen-host", "127.0.0.1",
             "-p", str(self.port), "-q",
             "--set", "upstream_cert=false",
             "--set", "connection_strategy=lazy"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(1.5)

    def status(self) -> dict:
        return {"running": self.running(), "port": self.port,
                "proxy_url": f"http://127.0.0.1:{self.port}" if self.running() else None,
                "ca_cert": os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")}

    async def stop(self) -> dict:
        if self._proc is not None:
            try:
                self._proc.terminate()
            except Exception:
                pass
        self._proc = None
        return {"running": False}


# standalone: python -m jsrecon.agent_proxy [port]
if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    ap = AgentProxy(port)
    ap.token = os.environ.get("JSRECON_TOKEN", "")
    print(f"[agent-proxy] mitmdump on 127.0.0.1:{port} -> {ap.jsrecon_url}")
    print(f"[agent-proxy] trust CA: ~/.mitmproxy/mitmproxy-ca-cert.pem (or run insecure)")
    print(f"[agent-proxy] use: dirsearch -u https://target --proxy http://127.0.0.1:{port}")

    async def _main():
        await ap.start()
        try:
            while ap.running():
                await asyncio.sleep(2)
        finally:
            await ap.stop()

    asyncio.run(_main())
