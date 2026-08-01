"""FastAPI web interface for jsrecon (multi-user)."""
from __future__ import annotations

import asyncio
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional
from .urlutil import safe_urlsplit as urlsplit

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import agent_proxy as agentproxymod
from . import analyzer, archive, auth, corpus, http_build, katana, openapi, pipeline, proxy as proxymod, sourcemaps, store, webpack
from .analyzer import Aggregator
from .filters import apply_filter
from .models import Endpoint, Finding
from .replay import BrowserPool

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
WORK_DIR = os.environ.get("JSRECON_WORKDIR", os.path.expanduser("~/project"))

app = FastAPI(title="jsrecon")
_browser = BrowserPool(headless=True)
_proxy = proxymod.MitmProxy(port=int(os.environ.get("JSRECON_PROXY_PORT", "8899")))
_browser.attach_cookie_store(_proxy.store)   # replay uses live harvested cookies
_proxy.jsrecon_url = os.environ.get("JSRECON_SELF_URL", "http://127.0.0.1:8777")
_proxy.token = auth.TOKEN                     # addon calls back into /api/exec/*
store.init()

# bearer/MCP acts as the owner account automatically (auth.mcp_user); an explicit
# JSRECON_MCP_USER still overrides if you ever want a separate principal.
auth.MCP_USER = os.environ.get("JSRECON_MCP_USER", auth.OPERATOR)


# ------------------------------ runtime state ------------------------------

@dataclass
class Job:
    id: str
    path: str
    owner: str
    source: str = "burp"
    status: str = "pending"
    stage: str = ""
    message: str = ""
    js_count: int = 0
    observed_count: int = 0
    corpus_dir: str = ""         # where the downloaded JS was persisted
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    proc: object = None          # katana subprocess (for stop)
    cancelled: bool = False
    log: list = field(default_factory=list)   # [{t, stage, message}] per stage
    _last_stage: str = ""

    def note(self, stage: str, message: str = "") -> None:
        """Update live status and append a timestamped log line on stage change."""
        self.stage = stage
        if message:
            self.message = message
        if stage != self._last_stage:
            self._last_stage = stage
            self.log.append({"t": round(time.time() - self.started, 1),
                             "stage": stage, "message": message or stage})


class Workspace:
    """Per-user merged, de-duplicated endpoints + findings (jsluice + gf)."""
    def __init__(self, user: str):
        self.user = user
        self.agg = Aggregator()
        self.findings: dict[str, Finding] = {}
        self.merged_jobs: set[str] = set()
        self.proxy = ""
        self.max_rps = float(os.environ.get("JSRECON_MAX_RPS", "0") or 0)  # 0 = unlimited
        self.auth_headers: dict[str, str] = {}   # applied to every send (e.g. Authorization)
        self._cache: Optional[list[Endpoint]] = None
        self._lock = threading.Lock()

    def merge_job(self, job: Job):
        with self._lock:
            if job.id in self.merged_jobs:
                return
            for e in job.endpoints:
                self.agg.add(Endpoint.from_dict(e.to_dict()))
            for f in job.findings:
                self.findings[f.key()] = f
            self.merged_jobs.add(job.id)
            self._cache = None

    def load(self, endpoints: list[Endpoint], findings: list[Finding]):
        with self._lock:
            self.agg = Aggregator()
            for e in endpoints:
                self.agg.add(e)
            self.findings = {f.key(): f for f in findings}
            self._cache = None

    def endpoints(self) -> list[Endpoint]:
        with self._lock:
            if self._cache is None:
                eps = self.agg.endpoints()
                analyzer.enrich(eps)
                self._cache = analyzer.collapse(eps)
            return self._cache

    def rehost(self, from_host: str, to_host: str) -> int:
        """Reassign every endpoint whose host == from_host to to_host, rebuilding
        the aggregator so it re-deduplicates under the new host. Returns count."""
        to_host = to_host.strip().replace("https://", "").replace("http://", "").strip("/")
        with self._lock:
            eps = self.agg.endpoints()
            n = 0
            for ep in eps:
                if ep.host == from_host:
                    ep.host = to_host
                    ep.url = f"{ep.scheme or 'https'}://{to_host}{ep.path}"
                    n += 1
            new = Aggregator()
            for ep in eps:
                new.add(ep)
            self.agg = new
            self._cache = None
            return n

    def clear(self):
        with self._lock:
            self.agg = Aggregator()
            self.findings = {}
            self.merged_jobs = set()
            self._cache = None

    def finding_list(self) -> list[Finding]:
        return list(self.findings.values())


JOBS: dict[str, Job] = {}
WORKSPACES: dict[str, Workspace] = {}


def _ws(user: str) -> Workspace:
    ws = WORKSPACES.get(user)
    if ws is None:
        ws = Workspace(user)
        WORKSPACES[user] = ws
    return ws


# ------------------------------ auth plumbing ------------------------------

_PUBLIC = {"/api/login", "/api/register", "/api/setup-state", "/health", "/favicon.ico"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static/") or path in _PUBLIC:
        return await call_next(request)
    if auth.principal(request) is not None:
        return await call_next(request)
    if path.startswith("/api"):
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    with open(os.path.join(STATIC_DIR, "login.html"), encoding="utf-8") as f:
        return HTMLResponse(f.read(), status_code=401)


def current_user(request: Request) -> str:
    p = auth.principal(request)
    if not p:
        raise HTTPException(401, "unauthorized")
    return p


class RegisterReq(BaseModel):
    username: str
    password: str


class LoginReq(BaseModel):
    username: str
    password: str


@app.get("/api/setup-state")
def setup_state():
    """Public: tells the login page whether registration is still open."""
    return {"registration_open": store.registration_open()}


@app.post("/api/register")
def register(req: RegisterReq):
    ok, msg = store.register(req.username.strip(), req.password)
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True}


@app.post("/api/login")
def login(req: LoginReq, response: Response):
    if not store.verify(req.username.strip(), req.password):
        raise HTTPException(401, "bad credentials")
    tok = auth.new_session(req.username.strip())
    response.set_cookie(auth.COOKIE_NAME, tok, httponly=True, samesite="lax")
    return {"ok": True, "username": req.username.strip()}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    auth.drop_session(request.cookies.get(auth.COOKIE_NAME, ""))
    response.delete_cookie(auth.COOKIE_NAME)
    return {"ok": True}


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/api/me")
def me(user: str = Depends(current_user)):
    ws = _ws(user)
    info = store.project_info(user) if store.valid_username(user) else {"exists": False}
    return {"username": user, "proxy": ws.proxy, "project": info,
            "combined": len(ws.endpoints())}


# ------------------------------ analysis jobs ------------------------------

class AnalyzeReq(BaseModel):
    path: str
    include_inline: bool = True
    include_traffic: bool = True
    ignore_strings: bool = False
    do_secrets: bool = True
    do_semgrep: bool = True
    verify_secrets: bool = False
    sourcemaps: bool = True
    fetch_remote_maps: bool = False
    webpack: bool = False
    concurrency: int = 8


def _run_analysis(job: Job, req: AnalyzeReq):
    try:
        job.status = "running"
        job.note("start", f"analyzing {os.path.basename(job.path)}")

        res = pipeline.run_recon(
            job.path, include_inline=req.include_inline, include_traffic=req.include_traffic,
            ignore_strings=req.ignore_strings, do_secrets=req.do_secrets,
            do_semgrep=req.do_semgrep, verify_secrets=req.verify_secrets,
            sourcemaps_expand=req.sourcemaps, fetch_remote_maps=req.fetch_remote_maps,
            webpack_expand=req.webpack, concurrency=req.concurrency,
            proxy=_ws(job.owner).proxy,
            progress=lambda stage, n: job.note(stage, f"{stage}: {n}"),
        )
        job.endpoints, job.findings = res.endpoints, res.findings
        job.js_count, job.observed_count = res.js_count, res.observed_count
        job.note("done", f"{len(job.endpoints)} endpoints, {len(job.findings)} findings "
                 f"({job.js_count} JS, {job.observed_count} traffic)")
        job.status = "done"
        _ws(job.owner).merge_job(job)
    except Exception as e:  # noqa: BLE001
        job.status = "error"
        job.error = repr(e)
        job.note("error", job.error)
    finally:
        job.finished = time.time()


@app.get("/api/files")
def list_files(dir: Optional[str] = None, user: str = Depends(current_user)):
    d = dir or WORK_DIR
    if not os.path.isdir(d):
        raise HTTPException(400, f"not a directory: {d}")
    entries = []
    for name in sorted(os.listdir(d)):
        full = os.path.join(d, name)
        if os.path.isfile(full) and name.lower().endswith(".xml"):
            entries.append({"name": name, "path": full, "size": os.path.getsize(full)})
    return {"dir": d, "files": entries}


@app.post("/api/analyze")
async def start_analyze(req: AnalyzeReq, user: str = Depends(current_user)):
    if not os.path.isfile(req.path):
        raise HTTPException(400, f"file not found: {req.path}")
    job = Job(id=uuid.uuid4().hex, path=req.path, owner=user, source="burp")
    JOBS[job.id] = job
    asyncio.get_event_loop().run_in_executor(None, _run_analysis, job, req)
    return {"job": job.id}


def _run_analysis_upload(job: Job, req: AnalyzeReq):
    try:
        _run_analysis(job, req)
    finally:
        try:
            os.remove(req.path)   # drop the temp upload once analyzed
        except OSError:
            pass


@app.post("/api/analyze-upload")
async def start_analyze_upload(
    file: UploadFile = File(...),
    include_inline: bool = Form(True),
    include_traffic: bool = Form(True),
    ignore_strings: bool = Form(False),
    do_secrets: bool = Form(True),
    do_semgrep: bool = Form(True),
    verify_secrets: bool = Form(False),
    sourcemaps: bool = Form(True),
    fetch_remote_maps: bool = Form(False),
    webpack: bool = Form(False),
    user: str = Depends(current_user),
):
    """Accept a Burp XML upload (streamed to a temp file) and analyze it — same
    pipeline as /api/analyze, no server-side path or folder needed."""
    updir = os.path.join(store.DATA_DIR, "uploads")
    os.makedirs(updir, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(file.filename or "upload.xml"))
    dest = os.path.join(updir, f"{uuid.uuid4().hex}-{safe}")
    with open(dest, "wb") as fh:
        while chunk := await file.read(1 << 20):   # 1 MiB chunks
            fh.write(chunk)
    await file.close()
    req = AnalyzeReq(
        path=dest, include_inline=include_inline, include_traffic=include_traffic,
        ignore_strings=ignore_strings, do_secrets=do_secrets, do_semgrep=do_semgrep,
        verify_secrets=verify_secrets, sourcemaps=sourcemaps,
        fetch_remote_maps=fetch_remote_maps, webpack=webpack)
    job = Job(id=uuid.uuid4().hex, path=dest, owner=user, source="burp")
    job.path = dest
    JOBS[job.id] = job
    asyncio.get_event_loop().run_in_executor(None, _run_analysis_upload, job, req)
    return {"job": job.id}


# ------------------------------ katana job ------------------------------

_AGENT_PROXY_PORT = int(os.environ.get("JSRECON_AGENT_PROXY_PORT", "8888"))
_agent_proxy = agentproxymod.AgentProxy(port=_AGENT_PROXY_PORT)
_agent_proxy.jsrecon_url = os.environ.get("JSRECON_SELF_URL", "http://127.0.0.1:8777")
_agent_proxy.token = auth.TOKEN


class KatanaReq(BaseModel):
    domain: str
    depth: int = 2
    headless: bool = False
    use_session: bool = True
    use_agent: bool = False
    do_secrets: bool = True
    do_semgrep: bool = True
    verify_secrets: bool = False
    sourcemaps: bool = True
    webpack: bool = True


async def _analyze_js_urls(job: Job, js_urls: list, req, prog, source: str):
    """Download JS URLs STRAIGHT to disk (no sources in RAM), split into part-500
    subdirs, then run jsluice+SAST directly over those files. Bounded memory."""
    rps = _ws(job.owner).max_rps
    dl_proxy = _ws(job.owner).proxy
    cdir = corpus.corpus_dir(job.owner, f"{source}-{job.path}")
    writer = corpus.Writer(cdir)             # wipes any previous partial run
    job.corpus_dir = cdir

    stop = lambda: job.cancelled
    rps_note = f" @ {rps:g} req/s" if rps > 0 else ""
    job.note("download", f"downloading {len(js_urls)} JS -> {cdir}{rps_note}")
    ok = await katana.download_to_disk(
        js_urls, _browser, writer, use_session=req.use_session,
        progress=prog, max_rps=rps, proxy=dl_proxy, should_stop=stop)
    writer.flush()
    job.note("download", f"saved {ok}/{len(js_urls)} JS to disk"
             + (" (stopped)" if job.cancelled else ""))
    if job.cancelled:
        writer.close(); job.js_count = writer.n
        job.note("stopped", f"stopped by user - {writer.n} JS kept on disk at {cdir}")
        job.endpoints, job.findings = [], []
        return

    # webpack: scan the saved files (batch by batch, bounded RAM) for new chunk
    # URLs and stream those to disk too
    if req.webpack and ok and not job.cancelled:
        have = corpus.all_urls(cdir)
        curls: list[str] = []
        seen: set[str] = set()
        for batch in corpus.iter_batches(cdir):
            for u in webpack.enumerate_from_js(batch, exclude=have):
                if u not in seen:
                    seen.add(u); curls.append(u)
            batch = None
        if curls:
            job.note("webpack", f"fetching {len(curls)} webpack chunks -> disk")
            got = await katana.download_to_disk(
                curls, _browser, writer, use_session=req.use_session,
                progress=prog, max_rps=rps, proxy=dl_proxy, should_stop=stop)
            writer.flush()
            job.note("webpack", f"saved {got} chunks")

    # source maps: expand batch by batch, write reconstructed originals to disk
    if req.sourcemaps and ok and not job.cancelled:
        async def _fetch_map(u: str):
            r = await _browser.send("GET", u, use_session=req.use_session, timeout_ms=20000)
            if r.get("ok") and r.get("body"):
                return r["body"].encode("utf-8", "replace")
            return None

        added = 0
        # iter_batches snapshots the existing part-dirs once, so originals we add
        # to new parts here are not re-scanned; memory stays bounded to one batch
        for batch in corpus.iter_batches(cdir):
            if job.cancelled:
                break
            originals = await sourcemaps.expand_remote(batch, _fetch_map)
            for o in originals:
                writer.add(o.url, o.source); added += 1
            batch = originals = None
        if added:
            writer.flush()
            job.note("sourcemaps", f"+{added} original files from source maps -> disk")

    writer.close()
    job.js_count = writer.n
    if job.cancelled:
        job.note("stopped", f"stopped by user - {writer.n} JS kept on disk at {cdir}")
        job.endpoints, job.findings = [], []
        return
    if not writer.n:
        job.note("download", "0 files saved - urls dead/blocked or no ServicePipe session")
        job.endpoints, job.findings = [], []
        return
    job.note("saved", f"corpus saved to {cdir} ({writer.n} JS, batches of {corpus.BATCH})")
    job.note("jsluice", f"jsluice + SAST on {writer.n} JS files (from disk, batched)")
    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(
        None, lambda: pipeline.run_recon_corpus(
            cdir, do_secrets=req.do_secrets, do_semgrep=req.do_semgrep,
            verify_secrets=req.verify_secrets, concurrency=8, should_stop=stop,
            progress=lambda stage, n: job.note(stage, f"{stage}: {n}")))
    job.endpoints, job.findings = res.endpoints, res.findings
    job.note("done", f"{len(job.endpoints)} endpoints, {len(job.findings)} findings "
             f"from {job.js_count} JS ({source})")


async def _run_katana_job(job: Job, req: KatanaReq):
    try:
        job.status = "running"
        job.note("crawl", f"katana crawling {req.domain}")

        def prog(stage, n):
            job.note(stage, f"{stage}: {n}")

        cookie = ""
        if req.use_session:
            url = req.domain if req.domain.startswith("http") else f"https://{req.domain}"
            cookie = (await _browser.get_cookies(url)).get("header", "")

        katana_proxy = (f"http://127.0.0.1:{_AGENT_PROXY_PORT}"
                        if req.use_agent else _ws(job.owner).proxy)
        urls = await katana.crawl_js(
            req.domain, depth=req.depth, headless=req.headless,
            cookie_header=cookie, proxy=katana_proxy, max_rps=_ws(job.owner).max_rps,
            progress=prog, on_proc=lambda p: setattr(job, "proc", p),
        )
        if job.cancelled:
            job.status = "error"
            job.error = "stopped by user"
            return
        job.note("crawl", f"crawled {len(urls)} js urls")
        await _analyze_js_urls(job, urls, req, prog, source="katana")
        job.status = "done"
        _ws(job.owner).merge_job(job)
    except Exception as e:  # noqa: BLE001
        job.status = "error"
        job.error = "stopped by user" if job.cancelled else repr(e)
        job.note("error", job.error)
    finally:
        job.finished = time.time()


@app.post("/api/katana")
async def start_katana(req: KatanaReq, user: str = Depends(current_user)):
    if not req.domain.strip():
        raise HTTPException(400, "domain required")
    job = Job(id=uuid.uuid4().hex, path=req.domain, owner=user, source="katana")
    JOBS[job.id] = job
    asyncio.create_task(_run_katana_job(job, req))
    return {"job": job.id}


# ------------------------------ archive job ------------------------------

class ArchiveReq(BaseModel):
    domain: str
    use_gau: bool = True
    use_wayback: bool = True
    subs: bool = True
    use_session: bool = True
    do_secrets: bool = True
    do_semgrep: bool = True
    verify_secrets: bool = False
    sourcemaps: bool = True
    webpack: bool = True


async def _run_archive_job(job: Job, req: ArchiveReq):
    try:
        job.status = "running"
        job.note("archive", f"gau + waybackurls on {req.domain}")

        def prog(stage, n):
            job.note(stage, f"{stage}: {n}")

        urls = await archive.gather_js_urls(
            req.domain, use_gau=req.use_gau, use_wayback=req.use_wayback,
            subs=req.subs, proxy=_ws(job.owner).proxy, progress=prog)
        if job.cancelled:
            job.status = "error"
            job.error = "stopped by user"
            return
        job.note("archive", f"{len(urls)} js urls from archives")
        await _analyze_js_urls(job, urls, req, prog, source="archive")
        job.status = "done"
        _ws(job.owner).merge_job(job)
    except Exception as e:  # noqa: BLE001
        job.status = "error"
        job.error = "stopped by user" if job.cancelled else repr(e)
        job.note("error", job.error)
    finally:
        job.finished = time.time()


@app.post("/api/archive")
async def start_archive(req: ArchiveReq, user: str = Depends(current_user)):
    if not req.domain.strip():
        raise HTTPException(400, "domain required")
    job = Job(id=uuid.uuid4().hex, path=req.domain, owner=user, source="archive")
    JOBS[job.id] = job
    asyncio.create_task(_run_archive_job(job, req))
    return {"job": job.id}


# --------------------------- scan a local JS dir ---------------------------
# Re-run jsluice + SAST over an already-downloaded corpus (from a crashed job or
# any directory of .js files) without re-crawling/re-downloading.

class ScanDirReq(BaseModel):
    path: str
    do_secrets: bool = True
    do_semgrep: bool = True
    verify_secrets: bool = False


async def _run_scandir_job(job: Job, req: ScanDirReq):
    try:
        job.status = "running"
        n = corpus.count(req.path)
        if not n:
            raise ValueError("no .js files found in that directory")
        job.corpus_dir = req.path
        job.note("jsluice", f"jsluice + SAST on {n} JS files (batched)")
        loop = asyncio.get_event_loop()
        res = await loop.run_in_executor(
            None, lambda: pipeline.run_recon_corpus(
                req.path, do_secrets=req.do_secrets, do_semgrep=req.do_semgrep,
                verify_secrets=req.verify_secrets, concurrency=8,
                should_stop=lambda: job.cancelled,
                progress=lambda stage, n: job.note(stage, f"{stage}: {n}")))
        job.js_count = res.js_count
        job.endpoints, job.findings = res.endpoints, res.findings
        job.note("done", f"{len(job.endpoints)} endpoints, {len(job.findings)} findings "
                 f"from {job.js_count} JS (scandir)")
        job.status = "done"
        _ws(job.owner).merge_job(job)
    except Exception as e:  # noqa: BLE001
        job.status = "error"
        job.error = repr(e)
        job.note("error", job.error)
    finally:
        job.finished = time.time()


@app.post("/api/scan-dir")
async def start_scandir(req: ScanDirReq, user: str = Depends(current_user)):
    p = req.path.strip()
    if not p:
        raise HTTPException(400, "path required")
    if not os.path.isdir(p):
        raise HTTPException(400, f"not a directory: {p}")
    job = Job(id=uuid.uuid4().hex, path=p, owner=user, source="scandir")
    JOBS[job.id] = job
    asyncio.create_task(_run_scandir_job(job, req))
    return {"job": job.id}


# --------------------------- scan a list of JS URLs ---------------------------
# Download a user-supplied list of .js URLs (e.g. from a .txt file) and run the
# same pipeline as katana/archive: webpack -> source maps -> jsluice + SAST.

class ScanUrlsReq(BaseModel):
    urls: list[str]
    use_session: bool = True
    do_secrets: bool = True
    do_semgrep: bool = True
    verify_secrets: bool = False
    sourcemaps: bool = True
    webpack: bool = True


async def _run_scanurls_job(job: Job, req: ScanUrlsReq):
    try:
        job.status = "running"

        def prog(stage, n):
            job.note(stage, f"{stage}: {n}")

        job.note("list", f"{len(req.urls)} JS urls from list")
        await _analyze_js_urls(job, req.urls, req, prog, source="urllist")
        job.status = "done"
        _ws(job.owner).merge_job(job)
    except Exception as e:  # noqa: BLE001
        job.status = "error"
        job.error = "stopped by user" if job.cancelled else repr(e)
        job.note("error", job.error)
    finally:
        job.finished = time.time()


@app.post("/api/scan-urls")
async def start_scanurls(req: ScanUrlsReq, user: str = Depends(current_user)):
    urls = [u.strip() for u in req.urls if u.strip()]
    if not urls:
        raise HTTPException(400, "no urls provided")
    req.urls = urls
    job = Job(id=uuid.uuid4().hex, path=f"{len(urls)} urls", owner=user, source="urllist")
    JOBS[job.id] = job
    asyncio.create_task(_run_scanurls_job(job, req))
    return {"job": job.id}


def _job(jid: str, user: str) -> Job:
    job = JOBS.get(jid)
    if not job or job.owner != user:
        raise HTTPException(404, "no such job")
    return job


@app.post("/api/jobs/{jid}/stop")
async def stop_job(jid: str, user: str = Depends(current_user)):
    job = _job(jid, user)
    job.cancelled = True
    if job.proc is not None:
        try:
            job.proc.kill()
        except Exception:
            pass
    return {"ok": True}


@app.get("/api/jobs/{jid}")
def job_status(jid: str, user: str = Depends(current_user)):
    job = _job(jid, user)
    return {
        "id": job.id, "status": job.status, "stage": job.stage, "source": job.source,
        "path": job.path, "message": job.message, "js_count": job.js_count,
        "observed_count": job.observed_count, "endpoints": len(job.endpoints),
        "findings": len(job.findings), "error": job.error, "corpus_dir": job.corpus_dir,
        "elapsed": round((job.finished or time.time()) - job.started, 1),
        "log": job.log,
    }


# --------------------------- shared list helpers ---------------------------

def _list_payload(all_eps: list[Endpoint], filter: str, exclude_static: bool,
                  limit: int = 0, offset: int = 0):
    eps = all_eps
    if exclude_static:
        eps = [e for e in eps if not e.is_static]
    if filter:
        try:
            eps = apply_filter(eps, filter)
        except Exception as e:
            raise HTTPException(400, f"bad filter: {e}")
    idx_of = {id(e): i for i, e in enumerate(all_eps)}
    total_matched = len(eps)
    page = eps[offset:offset + limit] if limit else eps[offset:]
    return {
        "count": total_matched, "total": len(all_eps),
        "returned": len(page), "offset": offset, "limit": limit or None,
        "endpoints": [
            {"idx": idx_of[id(e)], "method": e.method, "url": e.url, "path": e.path,
             "path_template": e.path_template or e.path, "count": e.count,
             "host": e.host, "category": e.category, "tags": e.tags,
             "query_params": e.query_params, "body_params": e.body_params,
             "has_param": e.has_param, "detect_type": e.detect_type}
            for e in page
        ],
    }


async def _endpoint_detail(ep: Endpoint):
    info = await _browser.get_cookies(ep.url)
    cookie = info.get("header", "")
    return {**ep.to_dict(), "raw_request": http_build.raw_request(ep, cookie=cookie),
            "session_cookie": cookie}


# ------------------------------ job views ------------------------------

@app.get("/api/jobs/{jid}/endpoints")
def job_endpoints(jid: str, filter: str = "", exclude_static: bool = True,
                  limit: int = 0, offset: int = 0,
                  user: str = Depends(current_user)):
    return _list_payload(_job(jid, user).endpoints, filter, exclude_static, limit, offset)


@app.get("/api/jobs/{jid}/endpoint/{idx}")
async def job_endpoint(jid: str, idx: int, user: str = Depends(current_user)):
    job = _job(jid, user)
    if idx >= len(job.endpoints):
        raise HTTPException(404, "not found")
    return await _endpoint_detail(job.endpoints[idx])


@app.get("/api/jobs/{jid}/findings")
def job_findings(jid: str, user: str = Depends(current_user)):
    job = _job(jid, user)
    return {"count": len(job.findings), "findings": [f.to_dict() for f in job.findings]}


# ------------------------------ combined views ------------------------------

@app.get("/api/combined/endpoints")
def combined_endpoints(filter: str = "", exclude_static: bool = True,
                       limit: int = 0, offset: int = 0,
                       user: str = Depends(current_user)):
    return _list_payload(_ws(user).endpoints(), filter, exclude_static, limit, offset)


@app.get("/api/combined/search")
def combined_search(domain: str = "", path_contains: str = "", method: str = "",
                    has_param: Optional[bool] = None, tag: str = "", category: str = "",
                    exclude_static: bool = True, limit: int = 100, offset: int = 0,
                    user: str = Depends(current_user)):
    """Structured search — no filter DSL. Every field is an AND-combined,
    case-insensitive substring/equality match. Robust alternative to `filter`."""
    all_eps = _ws(user).endpoints()
    dl, pl, ml, tl, cl = (domain.lower(), path_contains.lower(), method.lower(),
                          tag.lower(), category.lower())

    def keep(e: Endpoint) -> bool:
        if exclude_static and e.is_static:
            return False
        if dl and dl not in (e.host or "").lower():
            return False
        if pl and pl not in (e.path or "").lower() and pl not in (e.url or "").lower():
            return False
        if ml and ml != (e.method or "").lower():
            return False
        if cl and cl != (e.category or "").lower():
            return False
        if tl and tl not in [t.lower() for t in (e.tags or [])]:
            return False
        if has_param is not None and bool(e.has_param) != has_param:
            return False
        return True

    matched = [e for e in all_eps if keep(e)]
    idx_of = {id(e): i for i, e in enumerate(all_eps)}
    page = matched[offset:offset + limit] if limit else matched[offset:]
    return {
        "count": len(matched), "total": len(all_eps),
        "returned": len(page), "offset": offset, "limit": limit or None,
        "endpoints": [
            {"idx": idx_of[id(e)], "method": e.method, "url": e.url, "path": e.path,
             "path_template": e.path_template or e.path, "count": e.count,
             "host": e.host, "category": e.category, "tags": e.tags,
             "query_params": e.query_params, "body_params": e.body_params,
             "has_param": e.has_param, "detect_type": e.detect_type}
            for e in page
        ],
    }


@app.get("/api/combined/endpoint/{idx}")
async def combined_endpoint(idx: int, user: str = Depends(current_user)):
    eps = _ws(user).endpoints()
    if idx >= len(eps):
        raise HTTPException(404, "not found")
    return await _endpoint_detail(eps[idx])


@app.get("/api/combined/findings")
def combined_findings(user: str = Depends(current_user)):
    fs = _ws(user).finding_list()
    return {"count": len(fs), "findings": [f.to_dict() for f in fs]}


@app.get("/api/combined/hosts")
def combined_hosts(user: str = Depends(current_user)):
    return {"hosts": openapi.host_summary(_ws(user).endpoints())}


@app.get("/api/combined/domains")
def combined_domains(user: str = Depends(current_user)):
    """Every collected host with total + API(param) endpoint counts."""
    total: dict[str, int] = {}
    api: dict[str, int] = {}
    for ep in _ws(user).endpoints():
        h = ep.host or "(none)"
        total[h] = total.get(h, 0) + 1
        if not ep.is_static:
            api[h] = api.get(h, 0) + 1
    rows = [{"host": h, "total": c, "api": api.get(h, 0)} for h, c in total.items()]
    rows.sort(key=lambda x: (-x["api"], -x["total"], x["host"]))
    return {"count": len(rows), "domains": rows}


class RehostReq(BaseModel):
    from_host: str
    to_host: str


@app.post("/api/combined/rehost")
def combined_rehost(req: RehostReq, user: str = Depends(current_user)):
    """Reassign endpoints from one host to another (e.g. '?' -> api.yoomoney.ru)."""
    if not req.to_host.strip():
        raise HTTPException(400, "to_host required")
    n = _ws(user).rehost(req.from_host, req.to_host)
    return {"ok": True, "moved": n, "to_host": req.to_host.strip()}


@app.get("/api/combined/openapi.json")
def combined_openapi(filter: str = "", exclude_static: bool = True, host: str = "",
                     user: str = Depends(current_user)):
    eps = _ws(user).endpoints()
    if exclude_static:
        eps = [e for e in eps if not e.is_static]
    if filter:
        eps = apply_filter(eps, filter)
    return JSONResponse(openapi.build(eps, host=host or None))


@app.get("/api/combined/report.json")
def combined_report_json(filter: str = "", exclude_static: bool = True,
                         user: str = Depends(current_user)):
    ws = _ws(user)
    eps = ws.endpoints()
    if exclude_static:
        eps = [e for e in eps if not e.is_static]
    if filter:
        eps = apply_filter(eps, filter)
    return JSONResponse(content={
        "meta": {"user": user, "combined": True, "filter": filter},
        "count": len(eps), "endpoints": [e.to_dict() for e in eps],
        "findings": [f.to_dict() for f in ws.finding_list()]})


@app.get("/api/combined/report.md", response_class=PlainTextResponse)
def combined_report_md(filter: str = "", exclude_static: bool = True,
                       user: str = Depends(current_user)):
    ws = _ws(user)
    eps = ws.endpoints()
    if exclude_static:
        eps = [e for e in eps if not e.is_static]
    if filter:
        eps = apply_filter(eps, filter)
    return http_build.to_markdown_report(
        eps, meta={"user": user, "combined": True, "filter": filter or "(none)"},
        findings=ws.finding_list())


# ------------------------------ project save/load ------------------------------

@app.post("/api/project/save")
def project_save(user: str = Depends(current_user)):
    if not store.valid_username(user):
        raise HTTPException(400, "operator has no persistent project")
    ws = _ws(user)
    data = {
        "endpoints": [e.to_dict() for e in ws.endpoints()],
        "findings": [f.to_dict() for f in ws.finding_list()],
        "proxy": ws.proxy,
        "max_rps": ws.max_rps,
    }
    store.save_project(user, data)
    return {"ok": True, "endpoints": len(data["endpoints"]),
            "findings": len(data["findings"])}


@app.post("/api/project/load")
def project_load(user: str = Depends(current_user)):
    data = store.load_project(user)
    if not data:
        raise HTTPException(404, "no saved project")
    eps = [Endpoint.from_dict(d) for d in data.get("endpoints", [])]
    fs = [Finding.from_dict(d) for d in data.get("findings", [])]
    ws = _ws(user)
    ws.load(eps, fs)
    ws.proxy = data.get("proxy", "")
    ws.max_rps = float(data.get("max_rps", 0) or 0)
    _browser.set_proxy(ws.proxy)
    return {"ok": True, "endpoints": len(eps), "findings": len(fs)}


class ClearReq(BaseModel):
    delete_saved: bool = False   # also wipe the saved project file on disk


@app.post("/api/project/clear")
def project_clear(req: ClearReq, user: str = Depends(current_user)):
    """Empty the working project (in-memory endpoints/findings). With
    delete_saved=True also removes the persisted project file so it won't reload
    on next login."""
    _ws(user).clear()
    deleted = False
    if req.delete_saved and store.valid_username(user):
        deleted = store.delete_project(user)
    return {"ok": True, "cleared": True, "deleted_saved": deleted}


# ------------------------------ proxy settings ------------------------------

class ProxyReq(BaseModel):
    server: str = ""     # e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080


@app.post("/api/settings/proxy")
def set_proxy(req: ProxyReq, user: str = Depends(current_user)):
    ws = _ws(user)
    ws.proxy = req.server.strip()
    _browser.set_proxy(ws.proxy)
    return {"ok": True, "proxy": ws.proxy,
            "note": "restart the browser session to apply to it"}


@app.get("/api/settings/proxy")
def get_proxy(user: str = Depends(current_user)):
    return {"proxy": _ws(user).proxy}


# ------------------------------ rate limit ------------------------------

class RateReq(BaseModel):
    rps: float = 0     # max requests/sec for self-downloading tools; 0 = unlimited


@app.post("/api/settings/rate")
def set_rate(req: RateReq, user: str = Depends(current_user)):
    ws = _ws(user)
    ws.max_rps = max(0.0, float(req.rps or 0))
    return {"ok": True, "rps": ws.max_rps}


@app.get("/api/settings/rate")
def get_rate(user: str = Depends(current_user)):
    return {"rps": _ws(user).max_rps}


# -------------------- browser-agent execution queue --------------------
# The MITM proxy injects an agent into target pages; the agent polls this queue
# and runs each request via fetch() FROM the real (ServicePipe-passed) browser,
# which holds the live rolling token — beating ServicePipe's JS challenge.

_EXEC_QUEUE: list[dict] = []
_EXEC_LOCK = threading.Lock()   # /exec/next runs in a threadpool; guard pop() races
_EXEC_FUTURES: dict[str, asyncio.Future] = {}
_EXEC_AGENTS: dict[str, float] = {}     # origin -> last poll time
_EXEC_STORAGE: dict[str, dict] = {}     # origin -> {ls, ss, ts} captured by agent


def _agent_alive(origin: str) -> bool:
    return (time.time() - _EXEC_AGENTS.get(origin, 0)) < 15


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+")
_TOKKEY_RE = re.compile(r"tok|auth|bearer|jwt|access|session|api[_-]?key|id[_-]?token|credential", re.I)


def _extract_tokens(entry: dict) -> list[dict]:
    """Pull Bearer/JWT/token-like values out of a captured storage dump."""
    out = []
    for scope in ("ls", "ss"):
        for k, v in (entry.get(scope) or {}).items():
            v = v if isinstance(v, str) else str(v)
            jwt = _JWT_RE.search(v)
            if not (jwt or _TOKKEY_RE.search(k)):
                continue
            out.append({"scope": scope, "key": k, "jwt": bool(jwt),
                        "token": jwt.group(0) if jwt else v,
                        "preview": v[:200]})
    return out


def _registrable(host: str) -> str:
    """Crude registrable-domain: last two labels (kuper.ru from api.kuper.ru).
    Good enough to group *.kuper.ru siblings for cross-origin agent routing."""
    parts = host.split(":")[0].split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _pick_agent_origin(target_origin: str) -> Optional[str]:
    """Return the origin of an agent that can serve a request to target_origin.

    Prefer an agent living on the exact origin. Otherwise fall back to ANY live
    agent on the same registrable domain (e.g. web.kuper.ru's agent handling a
    request to api.kuper.ru) — a cross-origin credentialed fetch that still
    carries the target's ServicePipe cookies. Reading the body then depends on
    the target's CORS policy (usually OK for a site's own first-party API)."""
    if _agent_alive(target_origin):
        return target_origin
    treg = _registrable(urlsplit(target_origin).netloc)
    best, best_t = None, 0.0
    now = time.time()
    for o, t in _EXEC_AGENTS.items():
        if now - t < 15 and _registrable(urlsplit(o).netloc) == treg and t > best_t:
            best, best_t = o, t
    return best


class ExecResult(BaseModel):
    id: str
    ok: bool = True
    status: int = 0
    statusText: str = ""
    headers: dict = {}
    body: str = ""
    length: int = 0
    error: str = ""


@app.get("/api/exec/next")
def exec_next(origin: str = "", user: str = Depends(current_user)):
    if origin:
        _EXEC_AGENTS[origin] = time.time()
    with _EXEC_LOCK:
        for i, item in enumerate(_EXEC_QUEUE):
            if not origin or item.get("origin") == origin:
                return _EXEC_QUEUE.pop(i)
    return {}


@app.post("/api/exec/result")
def exec_result(res: ExecResult, user: str = Depends(current_user)):
    fut = _EXEC_FUTURES.pop(res.id, None)
    if fut and not fut.done():
        fut.set_result({
            "ok": res.ok, "status": res.status, "status_text": res.statusText,
            "headers": res.headers, "body": res.body,
            "length": res.length or len(res.body), "error": res.error,
            "via_agent": True,
        })
    return {"ok": True}


class StorageReq(BaseModel):
    origin: str = ""
    ls: dict = {}
    ss: dict = {}


@app.post("/api/exec/storage")
def exec_storage(req: StorageReq, user: str = Depends(current_user)):
    """Agent posts the page's localStorage/sessionStorage here (per origin)."""
    if req.origin:
        _EXEC_STORAGE[req.origin] = {"ls": req.ls, "ss": req.ss, "ts": time.time()}
    return {"ok": True}


@app.get("/api/storage")
def get_storage(origin: str = "", user: str = Depends(current_user)):
    """Captured web storage + extracted Bearer/JWT/token-like values per origin."""
    items = ({origin: _EXEC_STORAGE[origin]} if origin and origin in _EXEC_STORAGE
             else {} if origin else _EXEC_STORAGE)
    out = []
    for o, e in items.items():
        out.append({"origin": o, "ts": e.get("ts"),
                    "tokens": _extract_tokens(e),
                    "ls_keys": list((e.get("ls") or {}).keys()),
                    "ss_keys": list((e.get("ss") or {}).keys())})
    out.sort(key=lambda x: x.get("ts") or 0, reverse=True)
    return {"origins": out}


async def _exec_via_agent(method: str, url: str, headers: dict, body,
                          dispatch_origin: Optional[str] = None,
                          timeout: float = 60):
    rid = uuid.uuid4().hex[:12]
    parts = urlsplit(url)
    # where the job gets picked up (an agent's own origin) — may differ from the
    # target origin for cross-origin routing
    origin = dispatch_origin or f"{parts.scheme}://{parts.netloc}"
    h = {k: v for k, v in (headers or {}).items()
         if k.lower() not in ("cookie", "host", "content-length", "connection")}
    fut = asyncio.get_event_loop().create_future()
    _EXEC_FUTURES[rid] = fut
    _EXEC_QUEUE.append({"id": rid, "origin": origin, "method": method,
                        "url": url, "headers": h, "body": body})
    try:
        return await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        _EXEC_FUTURES.pop(rid, None)
        return {"ok": False, "error": "browser-agent timeout — keep a target page open"}


# ------------------------------ replay ------------------------------

class ReplayReq(BaseModel):
    cookies: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    override_url: Optional[str] = None
    override_method: Optional[str] = None
    override_body: object = None
    use_session: bool = True
    timeout_ms: int = 20000


async def _do_replay(ep: Endpoint, req: ReplayReq, owner: Optional[str] = None):
    method = req.override_method or ep.method
    if req.override_url:
        url = req.override_url
    else:
        query = http_build.build_query(ep)
        url = ep.url.split("?")[0] + (f"?{query}" if query else "")
    if req.override_body is not None:
        body = req.override_body
        headers = {**ep.headers, **(req.headers or {})}
    else:
        body, ctype = http_build.build_body(ep)
        headers = dict(ep.headers)
        if body and "Content-Type" not in headers:
            headers["Content-Type"] = ctype
        headers.update(req.headers or {})
    return await _send_dispatch(method, url, headers, body, req.cookies,
                                req.use_session, owner=owner,
                                timeout_ms=req.timeout_ms)


def _coerce_body(body):
    """Accept a JSON object/array as body (MCP frameworks auto-deserialize) and
    turn it back into a JSON string; leave strings/None untouched. Returns
    (body_str, is_json)."""
    if body is None or isinstance(body, str):
        return body, False
    try:
        import json as _json
        return _json.dumps(body, ensure_ascii=False), True
    except Exception:
        return str(body), False


async def _send_dispatch(method, url, headers, body, cookies, use_session,
                         owner: Optional[str] = None, timeout_ms: int = 20000):
    """Route a fully-formed request to the in-browser agent (beats ServicePipe's
    rolling token) when one is alive for the origin, else the Playwright browser."""
    headers = dict(headers or {})
    body, is_json = _coerce_body(body)
    if is_json and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"
    # apply per-project persistent auth headers unless already overridden
    if owner:
        for k, v in _ws(owner).auth_headers.items():
            if not any(hk.lower() == k.lower() for hk in headers):
                headers[k] = v
    origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
    agent_origin = _pick_agent_origin(origin)
    if agent_origin:
        return await _exec_via_agent(method, url, headers, body,
                                     dispatch_origin=agent_origin,
                                     timeout=max(1.0, timeout_ms / 1000))
    return await _browser.send(method, url, headers=headers, body=body,
                               cookies=cookies, use_session=use_session,
                               timeout_ms=timeout_ms)


class RawSendReq(BaseModel):
    method: str = "GET"
    url: str
    headers: Optional[dict[str, str]] = None
    body: object = None                 # str, or a JSON object/array (auto-encoded)
    cookies: Optional[str] = None
    use_session: bool = True
    timeout_ms: int = 20000


@app.post("/api/send")
async def send_raw(req: RawSendReq, user: str = Depends(current_user)):
    """Send a fully hand-crafted request (any method/url/headers/body). Routes
    through the browser agent when available — for the LLM to fuzz freely."""
    if not req.url.strip():
        raise HTTPException(400, "url required")
    return await _send_dispatch(req.method or "GET", req.url.strip(),
                                dict(req.headers or {}), req.body,
                                req.cookies, req.use_session,
                                owner=user, timeout_ms=req.timeout_ms)


class AuthReq(BaseModel):
    headers: Optional[dict[str, str]] = None   # e.g. {"Authorization": "Bearer ..."}
    clear: bool = False


@app.post("/api/settings/auth")
def set_auth(req: AuthReq, user: str = Depends(current_user)):
    """Persist headers auto-applied to every send for this project (e.g. an auth
    token), so the LLM doesn't repeat them each request."""
    ws = _ws(user)
    if req.clear:
        ws.auth_headers = {}
    elif req.headers:
        ws.auth_headers.update({k: v for k, v in req.headers.items()})
    return {"ok": True, "auth_headers": {k: "***" for k in ws.auth_headers}}


@app.get("/api/settings/auth")
def get_auth(user: str = Depends(current_user)):
    return {"auth_headers": {k: "***" for k in _ws(user).auth_headers}}


@app.post("/api/jobs/{jid}/replay/{idx}")
async def replay_job(jid: str, idx: int, req: ReplayReq, user: str = Depends(current_user)):
    job = _job(jid, user)
    if idx >= len(job.endpoints):
        raise HTTPException(404, "not found")
    return await _do_replay(job.endpoints[idx], req, owner=user)


@app.post("/api/combined/replay/{idx}")
async def replay_combined(idx: int, req: ReplayReq, user: str = Depends(current_user)):
    eps = _ws(user).endpoints()
    if idx >= len(eps):
        raise HTTPException(404, "not found")
    return await _do_replay(eps[idx], req, owner=user)


# --------------------------- browser session ---------------------------

class SessionReq(BaseModel):
    url: str = ""
    headed: bool = True
    cdp_url: str = ""          # attach to a real Chrome (--remote-debugging-port)
    channel: str = ""          # "chrome" / "msedge" to use a real browser build
    stealth: bool = True


@app.post("/api/session/start")
async def session_start(req: SessionReq, user: str = Depends(current_user)):
    try:
        return await _browser.start_session(
            url=req.url, headed=req.headed, cdp_url=req.cdp_url.strip(),
            channel=req.channel.strip(), stealth=req.stealth)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"session start failed: {e}")


@app.get("/api/session/status")
async def session_status(user: str = Depends(current_user)):
    st = await _browser.session_status()
    st["proxy"] = _proxy.status()
    st["agents"] = sum(1 for t in _EXEC_AGENTS.values() if time.time() - t < 15)
    return st


class ProxyStartReq(BaseModel):
    url: str = ""
    launch_browser: bool = True


@app.post("/api/session/proxy/start")
async def proxy_start(req: ProxyStartReq, user: str = Depends(current_user)):
    """Start the Burp-style MITM proxy and launch a plain (non-automated) Chromium
    through it. Solve ServicePipe in that window; live cookies are harvested and
    reused for replay automatically."""
    await _proxy.start()
    launched = _proxy.launch_browser(req.url.strip()) if req.launch_browser else False
    st = _proxy.status()
    st["browser_launched"] = launched
    st["hint"] = (f"Point your own browser at proxy 127.0.0.1:{_proxy.port} "
                  f"(trust its cert) if no window opened.") if not launched else ""
    return st


@app.post("/api/session/proxy/stop")
async def proxy_stop(user: str = Depends(current_user)):
    return await _proxy.stop()


@app.get("/api/session/proxy/status")
async def proxy_status(user: str = Depends(current_user)):
    return _proxy.status()


class PinReq(BaseModel):
    host: str = ""


def _pin_host(raw: str) -> str:
    """Accept a bare host or a full URL, return the host."""
    raw = (raw or "").strip()
    if "://" in raw:
        raw = urlsplit(raw).netloc
    return raw.split("/")[0].split(":")[0]


@app.get("/api/agent/pins")
async def agent_pins(user: str = Depends(current_user)):
    return {"pins": _proxy.pins()}


@app.post("/api/agent/pin")
async def agent_pin(req: PinReq, user: str = Depends(current_user)):
    host = _pin_host(req.host)
    if not host:
        raise HTTPException(400, "host required")
    return {"ok": True, "pins": _proxy.add_pin(host)}


@app.post("/api/agent/unpin")
async def agent_unpin(req: PinReq, user: str = Depends(current_user)):
    return {"ok": True, "pins": _proxy.remove_pin(_pin_host(req.host))}


@app.get("/api/session/cookies")
async def session_cookies(url: str = "", user: str = Depends(current_user)):
    return await _browser.get_cookies(url)


class ManualCookiesReq(BaseModel):
    url: str
    cookie_header: str
    headed: bool = False


@app.post("/api/session/cookies/set")
async def session_set_cookies(req: ManualCookiesReq, user: str = Depends(current_user)):
    """Inject cookies grabbed from your working browser (Burp/Chrome) — the
    reliable way past ServicePipe (no captcha, requests ride Chrome's TLS)."""
    if not req.url.strip() or not req.cookie_header.strip():
        raise HTTPException(400, "url and cookie_header required")
    try:
        return await _browser.set_manual_cookies(
            req.url.strip(), req.cookie_header.strip(), headed=req.headed)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"set cookies failed: {e}")


@app.post("/api/session/stop")
async def session_stop(user: str = Depends(current_user)):
    return await _browser.stop_session()


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8") as f:
        return f.read()


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/api/agent-proxy/status")
async def agent_proxy_status(_: str = Depends(current_user)):
    return _agent_proxy.status()


@app.on_event("startup")
async def _startup():
    auth.print_banner()
    try:
        await _agent_proxy.start()
    except Exception as e:
        print(f"[agent-proxy] failed to start on port {_AGENT_PROXY_PORT}: {e}")


@app.on_event("shutdown")
async def _shutdown():
    await _agent_proxy.stop()
    await _proxy.stop()
    await _browser.close()
