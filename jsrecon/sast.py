"""Passive SAST over the JS corpus: jsluice secrets + trufflehog + semgrep.

Runs automatically during analysis (including files reconstructed from source
maps). All three tools work off a single materialized temp dir. Results become
Finding objects, deduplicated, with severity.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
from typing import Iterable, Optional

from .analyzer import JSLUICE_BIN
from .models import Finding, JsFile

TRUFFLEHOG_BIN = os.environ.get(
    "TRUFFLEHOG_BIN", shutil.which("trufflehog") or os.path.expanduser("~/go/bin/trufflehog"))
SEMGREP_BIN = os.environ.get("SEMGREP_BIN", shutil.which("semgrep") or "semgrep")
SEMGREP_CONFIG = os.environ.get(
    "JSRECON_SEMGREP_CONFIG", os.path.join(os.path.dirname(__file__), "rules", "jsrecon-js.yml"))

_JSLUICE_SEV = {
    "AWSAccessKey": "high", "gcpServiceAccount": "high", "privateKey": "high",
    "githubKey": "high", "slackToken": "high", "stripeKey": "high",
    "jwt": "medium", "authorizationBasic": "medium", "authorizationBearer": "medium",
}
_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

# --- memory guards for large corpora (11k+ minified bundles OOM a 16GB box) ---
# semgrep parses every file's AST at once; running the whole dir explodes RAM.
# Batch the files, cap semgrep's own memory, single-process, and skip giant
# minified bundles that blow the AST up with little SAST value.
_SEM_BATCH = int(os.environ.get("JSRECON_SEMGREP_BATCH", "300"))
_SEM_MAXMEM_MB = os.environ.get("JSRECON_SEMGREP_MAXMEM_MB", "2000")
_SEM_MAX_FILE_KB = int(os.environ.get("JSRECON_SEMGREP_MAX_FILE_KB", "2000"))


def _materialize(js_files: Iterable[JsFile], tmp: str):
    manifest: dict[str, str] = {}
    paths: list[str] = []
    for i, jf in enumerate(js_files):
        name = os.path.join(tmp, f"{i:07d}.js")
        try:
            with open(name, "w", encoding="utf-8") as fh:
                fh.write(jf.source)
        except Exception:
            continue
        manifest[name] = jf.base_url()
        paths.append(name)
    return manifest, paths


def _feed_stdin(proc, paths):
    def _feed():
        try:
            for p in paths:
                proc.stdin.write(p + "\n")
            proc.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            proc.stdin.close()
    t = threading.Thread(target=_feed, daemon=True)
    t.start()
    return t


def _jsluice_secrets(paths, manifest, concurrency) -> list[Finding]:
    proc = subprocess.Popen(
        [JSLUICE_BIN, "secrets", "-c", str(concurrency)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    t = _feed_stdin(proc, paths)
    out: list[Finding] = []
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = rec.get("kind", "secret")
        data = rec.get("data") or {}
        evidence = data.get("key") or json.dumps(data, ensure_ascii=False)
        out.append(Finding(
            kind=kind, severity=_JSLUICE_SEV.get(kind, rec.get("severity") or "low"),
            source="jsluice-secrets", evidence=str(evidence)[:300],
            location=manifest.get(rec.get("filename", ""), "")))
    proc.wait()
    t.join(timeout=5)
    return out


def _trufflehog(tmp, manifest, verify) -> list[Finding]:
    if not (TRUFFLEHOG_BIN and os.path.exists(TRUFFLEHOG_BIN)):
        return []
    cmd = [TRUFFLEHOG_BIN, "filesystem", tmp, "--json", "--no-update"]
    if not verify:
        cmd.append("--no-verification")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except Exception:
        return []
    out: list[Finding] = []
    for line in proc.stdout.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        det = rec.get("DetectorName")
        if not det:
            continue
        fpath = (rec.get("SourceMetadata", {}).get("Data", {})
                 .get("Filesystem", {}).get("file", ""))
        verified = bool(rec.get("Verified"))
        out.append(Finding(
            kind=f"trufflehog:{det}",
            severity="high" if verified else "medium",
            source="trufflehog",
            evidence=(rec.get("Raw") or rec.get("Redacted") or "")[:120]
                     + (" [VERIFIED-LIVE]" if verified else ""),
            location=manifest.get(fpath, fpath),
            extra={"verified": verified}))
    return out


def _semgrep_batch(batch, manifest) -> list[Finding]:
    """Run semgrep over one batch of file paths with a hard memory cap."""
    cmd = [SEMGREP_BIN, "--config", SEMGREP_CONFIG, "--json", "--quiet",
           "--disable-version-check", "--metrics=off", "--timeout", "20",
           "--max-memory", str(_SEM_MAXMEM_MB), "--jobs", "1", *batch]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                              env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
    except Exception:
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    out: list[Finding] = []
    for r in data.get("results", []):
        cid = (r.get("check_id") or "").split(".")[-1]
        extra = r.get("extra", {})
        sev = _SEMGREP_SEV.get(extra.get("severity", "INFO"), "low")
        line = r.get("start", {}).get("line", "?")
        out.append(Finding(
            kind=f"semgrep:{cid}", severity=sev, source="semgrep",
            evidence=f"{extra.get('message','')[:160]} (L{line})",
            location=manifest.get(r.get("path", ""), r.get("path", ""))))
    return out


def _semgrep(paths, manifest, progress=None) -> list[Finding]:
    if not shutil.which(SEMGREP_BIN):
        return []
    # skip giant minified bundles: they blow up semgrep's AST for little gain
    cap = _SEM_MAX_FILE_KB * 1024
    scan = []
    for p in paths:
        try:
            if os.path.getsize(p) <= cap:
                scan.append(p)
        except OSError:
            continue
    out: list[Finding] = []
    for i in range(0, len(scan), _SEM_BATCH):
        out += _semgrep_batch(scan[i:i + _SEM_BATCH], manifest)
        if progress:
            progress("semgrep", min(i + _SEM_BATCH, len(scan)))
    return out


def run_sast(
    js_files: list[JsFile],
    do_secrets: bool = True,
    do_semgrep: bool = True,
    verify_secrets: bool = False,
    concurrency: int = 8,
    progress: Optional[callable] = None,
) -> list[Finding]:
    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="jsrecon_sast_") as tmp:
        manifest, paths = _materialize(js_files, tmp)
        if not paths:
            return []
        if do_secrets:
            if progress:
                progress("secrets", len(paths))
            findings += _jsluice_secrets(paths, manifest, concurrency)
            findings += _trufflehog(tmp, manifest, verify_secrets)
        if do_semgrep:
            if progress:
                progress("semgrep", 0)
            findings += _semgrep(paths, manifest, progress=progress)

    return _dedup(findings)


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        k = f.key()
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def run_sast_dir(
    dir_path: str,
    base_map: dict,
    do_secrets: bool = True,
    do_semgrep: bool = True,
    verify_secrets: bool = False,
    concurrency: int = 8,
    progress: Optional[callable] = None,
) -> list[Finding]:
    """SAST directly over a dir of .js files ALREADY on disk (a corpus part) —
    no temp copy, no sources in memory. base_map maps full path -> original URL."""
    paths = sorted(base_map.keys())
    if not paths:
        return []
    findings: list[Finding] = []
    if do_secrets:
        findings += _jsluice_secrets(paths, base_map, concurrency)
        findings += _trufflehog(dir_path, base_map, verify_secrets)
    if do_semgrep:
        findings += _semgrep(paths, base_map, progress=progress)
    return _dedup(findings)
