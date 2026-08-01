# jsrecon

A JavaScript‑recon toolkit for authorized bug‑bounty / pentest work. Point it at
a target's JavaScript — from a Burp export, a live crawl, web archives, or a
plain URL list — and it downloads every `.js`, extracts endpoints, parameters
and secrets (jsluice + trufflehog + semgrep), reconstructs source maps and
webpack chunks, and lets you replay requests through a real browser session that
bypasses ServicePipe anti‑bot. A web UI and an MCP server (drive it from an LLM)
sit on top.

---

## 1. Install

Two ways. **Docker** is self‑contained (all external tools baked in). **Local**
needs a few Go/Python tools on your machine.

### Option A — Docker (recommended)

```bash
git clone <your-repo-url> jsrecon && cd jsrecon
docker compose up -d --build          # first build compiles the Go tools, takes a while
```

The UI is now on **http://127.0.0.1:8777**. Data (users, token, saved projects,
JS corpora) persists in the `jsrecon-data` volume.

### Option B — Local (venv)

Needs Python 3.11+, Go, and Chromium. Install the external tools once:

```bash
# Go tools
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
# trufflehog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ~/go/bin
# gf vulnerability patterns
git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns ~/.gf

# Python env (semgrep, mitmproxy, playwright come from requirements.txt)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install --with-deps chromium
```

Tools are looked up on `PATH` / `~/go/bin`; override any with env vars
(`JSLUICE_BIN`, `KATANA_BIN`, `GAU_BIN`, `WAYBACKURLS_BIN`, `TRUFFLEHOG_BIN`,
`SEMGREP_BIN`).

---

## 2. Run

```bash
# Docker
docker compose up -d

# Local
./start.sh            # == uvicorn jsrecon.server:app --host 127.0.0.1 --port 8777
```

Open **http://127.0.0.1:8777**.

**First run:** registration is open only until the first account exists. Open the
UI, create the **owner** account (login + password) — after that registration is
closed and you just log in. No registration codes, no auth env vars.

Print the auth state / API token any time:

```bash
python -m jsrecon.admin status                    # local
docker exec jsrecon python -m jsrecon.admin status # docker
```

---

## 3. Connect the MCP server (drive jsrecon from an LLM)

The MCP server is a thin client over the running jsrecon server, so the model
shares your live jobs, workspace and browser session. The API token is read
automatically from `~/.jsrecon_data/token` — no token env needed for a local run.

```bash
claude mcp add jsrecon \
  -e PYTHONPATH=/absolute/path/to/jsrecon \
  -- /absolute/path/to/jsrecon/.venv/bin/python -m jsrecon.mcp_server
```

- `PYTHONPATH` must point at the repo root so the `jsrecon` package resolves.
- Point at a non‑default server with `-e JSRECON_URL=http://127.0.0.1:8777`.
- **Docker:** the token lives in the container volume — pass it explicitly:
  `-e JSRECON_TOKEN="$(docker exec jsrecon cat /data/token)"`.

The model can then list/search endpoints, read params/secrets/findings, send
requests through your browser session, set auth headers, start katana/archive
jobs, and more.

---

## What it does

### Sources (tabs in the UI)

| Tab | What it does |
|-----|--------------|
| **Burp XML** | Upload a Burp export (`.xml`) — streamed to the server. Extracts JS from responses + inline `<script>`, merges real observed traffic, expands source maps / webpack chunks. |
| **Katana** | Crawl a live domain, collect `.js`, download and analyze. Can ride the browser session (ServicePipe bypass) or go through the browser‑agent proxy. |
| **Archive** | Pull historical `.js` URLs from `gau` + `waybackurls` (incl. removed‑from‑site files), download and analyze. |
| **Каталог** | Run jsluice + SAST over an **already‑downloaded** corpus directory — no re‑download. Used to resume after an interruption. |
| **Список URL** | Upload a `.txt` of `.js` URLs (one per line); download and analyze them with the same pipeline. |

Everything from every source merges into one deduplicated project.

### Analysis pipeline

- **Endpoints** via jsluice — method, path, query/body params, headers.
- **Secrets** via jsluice‑secrets + trufflehog (optionally verify keys are live).
- **SAST** via semgrep (DOM‑XSS, `eval`, `postMessage`, injection sinks…).
- **Source maps** — inline always, remote fetched on demand (reconstructs
  original TypeScript/JS).
- **Webpack** — enumerates and downloads lazily‑loaded chunks.

Findings land in **Находки**; endpoints in **Проект**.

### Unknown‑host handling

A relative path in JS (`/api/v1/x`) has no host of its own — in the real SPA the
browser resolves it against the *page* origin, not the CDN the bundle was served
from. So jsrecon marks such endpoints **host `?`** ("❓ неизвестный хост") instead
of guessing; only absolute / protocol‑relative URLs keep their real host.

In the **🌐 Домены** tab you see every collected host with endpoint counts and can
**rebase** a host: click *"→ задать хост"* on `?` (or *"→ заменить хост"* on any
host) to reassign those endpoints to the real API domain (e.g. `api.yoomoney.ru`).
The list re‑deduplicates under the new host.

### Replay + ServicePipe bypass

- **Прокси‑браузер** — launches a real Chromium through a MITM proxy (like Burp).
  It captures live cookies and injects a JS agent that runs `fetch()` from inside
  the ServicePipe‑passed page, so replayed requests carry the rolling anti‑bot
  token. `--disable-web-security` lets the agent read cross‑origin responses.
- **Domain pinning** (⚙) — for subdomains that 302 away, the agent serves a stub
  on top‑level navigation so the tab stays on the origin you want to test.
- **Token collection** (⚙ → 🔑) — the agent harvests `localStorage` /
  `sessionStorage` Bearer/JWT tokens (which aren't cookies) so you can feed one to
  `set_auth`.
- **Agent HTTP proxy** — external tools (dirsearch, ffuf, curl, katana) can go
  through `--proxy http://127.0.0.1:8888` to inherit the ServicePipe bypass.

### Filtering & exports

- Filter box: `domain=*yoomoney.ru && method=GET && has_param`.
- Exports honor the current filter: **Swagger** (OpenAPI JSON), **JSON**, **MD**.

### Settings (⚙)

- **Upstream proxy** — routes all self‑downloading tools through an HTTP proxy
  (empty = direct).
- **Rate limit (`req/s`)** — global cap on requests/sec across every
  self‑downloading tool (`0` = unlimited). Set it to be polite / avoid IP bans.
- **Domain pins**, **agent tokens**, **save / clear project**.

---

## How data is stored (and why runs survive crashes)

Downloads stream **straight to disk**, one file at a time — nothing is held in
RAM — split into `part-NNNN/` subdirs of 500 files each:

```
~/.jsrecon_data/jscorpus/<user>/<source>-<target>/part-0000/…  (+ _manifest.json)
```

Analysis then runs jsluice/semgrep **directly on those files**, one part at a
time, so a 15k‑file corpus never blows up memory. If a run is interrupted (or you
get IP‑banned mid‑download), the files already on disk stay — point the
**Каталог** tab at that directory to finish the SAST without re‑downloading.

Persistent data lives under `JSRECON_DATA` (default `~/.jsrecon_data`, `/data` in
Docker): `users.json`, `token`, `projects/<user>.json`, and `jscorpus/`.

---

## Environment variables

| Var | Default | Purpose |
|-----|---------|---------|
| `JSRECON_DATA` | `~/.jsrecon_data` | persistent data dir |
| `JSRECON_WORKDIR` | `~/project` | legacy default folder for server‑side Burp XML |
| `JSRECON_TOKEN` | auto (`$DATA/token`) | API/bearer token; auto‑generated & persisted |
| `JSRECON_MCP_USER` | owner account | principal the bearer/MCP acts as |
| `JSRECON_MAX_RPS` | `0` | default global download rate limit |
| `JSRECON_CORPUS_BATCH` | `500` | files per part‑subdir |
| `JSRECON_AGENT_PROXY_PORT` | `8888` | port for the external‑tool agent proxy |
| `JSRECON_SEMGREP_BATCH` / `_MAXMEM_MB` / `_MAX_FILE_KB` | `300` / `2000` / `2000` | semgrep memory guards |
| `JSLUICE_BIN`, `KATANA_BIN`, `GAU_BIN`, `WAYBACKURLS_BIN`, `TRUFFLEHOG_BIN`, `SEMGREP_BIN` | on PATH | external tool overrides |

---

## Security notes

- Bind to localhost only. For remote use, put nginx + TLS in front — the app has
  no transport security of its own.
- The proxy‑browser runs with `--disable-web-security`; use it only for testing.
- Only use against targets you are authorized to test.
