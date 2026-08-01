"""SAST layer: jsluice secrets over the extracted JS."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
from typing import Iterable

from .analyzer import JSLUICE_BIN
from .models import Finding, JsFile

# jsluice reports "low" for everything; bump a few known-nasty kinds.
_SEV_BUMP = {
    "AWSAccessKey": "high", "gcpServiceAccount": "high", "privateKey": "high",
    "githubKey": "high", "slackToken": "high", "stripeKey": "high",
    "jwt": "medium", "authorizationBasic": "medium", "authorizationBearer": "medium",
}


def scan_secrets(js_files: Iterable[JsFile], concurrency: int = 8) -> list[Finding]:
    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="jsrecon_sec_") as tmp:
        base_map: dict[str, str] = {}
        paths: list[str] = []
        for i, jf in enumerate(js_files):
            name = os.path.join(tmp, f"{i:07d}.js")
            try:
                with open(name, "w", encoding="utf-8") as fh:
                    fh.write(jf.source)
            except Exception:
                continue
            base_map[name] = jf.base_url()
            paths.append(name)
        if not paths:
            return []

        proc = subprocess.Popen(
            [JSLUICE_BIN, "secrets", "-c", str(concurrency)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
        )
        assert proc.stdin and proc.stdout

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

        seen: set[str] = set()
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
            loc = base_map.get(rec.get("filename", ""), "")
            dedup = f"{kind}:{evidence}"
            if dedup in seen:
                continue
            seen.add(dedup)
            findings.append(Finding(
                kind=kind,
                severity=_SEV_BUMP.get(kind, rec.get("severity") or "low"),
                source="jsluice-secrets",
                evidence=str(evidence)[:300],
                location=loc,
                extra={"raw_severity": rec.get("severity")},
            ))
        proc.wait()
        t.join(timeout=5)
    return findings
