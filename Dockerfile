# syntax=docker/dockerfile:1

# ---------- stage 1: build the Go tools (jsluice, katana, gf) ----------
FROM golang:1.25-bookworm AS gobuild
# katana needs Go >= 1.25.7; GOTOOLCHAIN=auto lets go fetch the exact toolchain
ENV GOBIN=/tools GOFLAGS=-buildvcs=false GOTOOLCHAIN=auto
RUN mkdir -p /tools && \
    go install github.com/BishopFox/jsluice/cmd/jsluice@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/tomnomnom/gf@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# ---------- stage 2: runtime ----------
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    JSLUICE_BIN=/usr/local/bin/jsluice \
    KATANA_BIN=/usr/local/bin/katana \
    CHROMIUM_PATH=/usr/bin/chromium \
    GF_DIR=/opt/gf-patterns \
    JSRECON_DATA=/data \
    JSRECON_WORKDIR=/work \
    JSRECON_NO_SANDBOX=1

# system deps: chromium (for katana headless + as a browser), git for gf patterns
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium git curl ca-certificates fonts-liberation tini \
    && rm -rf /var/lib/apt/lists/*

# Go tools from the build stage
COPY --from=gobuild /tools/jsluice      /usr/local/bin/jsluice
COPY --from=gobuild /tools/katana       /usr/local/bin/katana
COPY --from=gobuild /tools/gf           /usr/local/bin/gf
COPY --from=gobuild /tools/waybackurls  /usr/local/bin/waybackurls
COPY --from=gobuild /tools/gau          /usr/local/bin/gau

# gf vulnerability patterns (jsrecon reads these JSON files directly)
RUN git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /opt/gf-patterns

# trufflehog (verified-secret scanner) — installed via official script (go install
# fails on its go.mod replace directives). Retry: the GitHub release download can
# time out on flaky networks.
RUN for i in 1 2 3 4 5; do \
      curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin && break; \
      echo "trufflehog install retry $i…"; sleep 10; \
    done; \
    test -x /usr/local/bin/trufflehog

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    playwright install --with-deps chromium

COPY jsrecon ./jsrecon

RUN mkdir -p /data /work
VOLUME ["/data", "/work"]
EXPOSE 8777

# tini for correct signal handling; bind 0.0.0.0 INSIDE the container
# (publish only to 127.0.0.1 on the host — see docker-compose.yml)
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "jsrecon.server:app", "--host", "0.0.0.0", "--port", "8777"]
