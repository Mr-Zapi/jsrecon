"""Persist a downloaded JS corpus to disk and read it back in bounded batches, so
an analysis over a huge corpus (10k+ minified bundles) never has to hold every
source in RAM at once — that is what OOM-kills the server. Files are split into
`part-NNNN/` subdirs of BATCH files each; analysis runs one subdir at a time.

Layout under JSRECON_DATA/jscorpus/<user>/<name>/:
    part-0000/0000000.js .. 0000499.js  + _manifest.json  {filename: url}
    part-0001/0000000.js .. 0000499.js  + _manifest.json
    ...
Older flat corpora (files + _manifest.json directly in <name>/) are still read.
"""
from __future__ import annotations

import json
import os
import re

from .models import JsFile
from .store import DATA_DIR

_CORPUS = os.path.join(DATA_DIR, "jscorpus")
_SAFE = re.compile(r"[^a-zA-Z0-9._-]+")
BATCH = int(os.environ.get("JSRECON_CORPUS_BATCH", "500"))


def _slug(name: str) -> str:
    s = _SAFE.sub("_", (name or "corpus").strip()).strip("._-")
    return s[:80] or "corpus"


def corpus_dir(user: str, name: str) -> str:
    return os.path.join(_CORPUS, _slug(user), _slug(name))


class Writer:
    """Streams downloaded JS straight to disk, one file at a time, split into
    part-NNNN subdirs of `batch` files. Holds NOTHING in memory except the small
    current-part manifest (filename -> url). This is what lets a 15k-file
    download run on a 16GB box without OOM."""

    def __init__(self, base: str, batch: int = 0, reset: bool = True):
        import shutil
        self.base = base
        self.batch = batch or BATCH
        if reset and os.path.isdir(base):
            shutil.rmtree(base, ignore_errors=True)
        os.makedirs(base, exist_ok=True)
        self.n = 0              # total files written
        self._part = -1
        self._in_part = self.batch   # force a rotate on first add
        self._pdir = None
        self._manifest: dict[str, str] = {}

    def _flush(self):
        if self._pdir is None:
            return
        tmp = os.path.join(self._pdir, "_manifest.json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._manifest, fh, ensure_ascii=False)
        os.replace(tmp, os.path.join(self._pdir, "_manifest.json"))

    def _rotate(self):
        self._flush()
        self._part += 1
        self._pdir = os.path.join(self.base, f"part-{self._part:04d}")
        os.makedirs(self._pdir, exist_ok=True)
        self._manifest = {}
        self._in_part = 0

    def add(self, url: str, source: str):
        if self._in_part >= self.batch:
            self._rotate()
        fn = f"{self._in_part:07d}.js"
        try:
            with open(os.path.join(self._pdir, fn), "w", encoding="utf-8", errors="replace") as fh:
                fh.write(source)
        except Exception:
            return
        self._manifest[fn] = url
        self._in_part += 1
        self.n += 1

    def flush(self):
        """Persist the current part's manifest so it can be read mid-run."""
        self._flush()

    def close(self):
        self._flush()


def _write_batch(bdir: str, files: list[JsFile]) -> None:
    os.makedirs(bdir, exist_ok=True)
    manifest: dict[str, str] = {}
    for i, jf in enumerate(files):
        fn = f"{i:07d}.js"
        try:
            with open(os.path.join(bdir, fn), "w", encoding="utf-8") as fh:
                fh.write(jf.source)
        except Exception:
            continue
        manifest[fn] = jf.url
    tmp = os.path.join(bdir, "_manifest.json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False)
    os.replace(tmp, os.path.join(bdir, "_manifest.json"))


def save(user: str, name: str, js_files: list[JsFile], batch: int = 0) -> str:
    """Write the corpus split into part-NNNN subdirs of `batch` files each.
    Returns the base directory path."""
    batch = batch or BATCH
    base = corpus_dir(user, name)
    os.makedirs(base, exist_ok=True)
    for bi in range(0, max(1, (len(js_files) + batch - 1) // batch)):
        chunk = js_files[bi * batch:(bi + 1) * batch]
        if not chunk and bi > 0:
            break
        _write_batch(os.path.join(base, f"part-{bi:04d}"), chunk)
    return base


def _load_dir(path: str) -> list[JsFile]:
    """Load JsFiles from a single directory (manifest-driven, else *.js)."""
    manifest = {}
    mpath = os.path.join(path, "_manifest.json")
    if os.path.exists(mpath):
        try:
            with open(mpath, encoding="utf-8") as fh:
                manifest = json.load(fh)
        except Exception:
            manifest = {}
    if manifest:
        items = sorted(manifest.items())
    else:
        items = [(fn, "file://" + os.path.join(path, fn))
                 for fn in sorted(os.listdir(path)) if fn.endswith(".js")]
    out: list[JsFile] = []
    for fn, url in items:
        fp = os.path.join(path, fn)
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except Exception:
            continue
        out.append(JsFile(url=url or ("file://" + fp), source=src,
                          origin="corpus", host=""))
    return out


def _part_dirs(path: str) -> list[str]:
    return sorted(os.path.join(path, d) for d in os.listdir(path)
                  if d.startswith("part-") and os.path.isdir(os.path.join(path, d)))


def iter_labeled_batches(path: str):
    """Yield (label, files) one part-subdir at a time (bounded memory). `label`
    is a human path/range for logging. Falls back to chunking a flat dir."""
    if not os.path.isdir(path):
        raise NotADirectoryError(path)
    parts = _part_dirs(path)
    if parts:
        for p in parts:
            yield p, _load_dir(p)
    else:
        # flat corpus or a user-supplied dir of .js files: chunk it ourselves
        js = [fn for fn in sorted(os.listdir(path)) if fn.endswith(".js")]
        if js:
            all_files = _load_dir(path)
            for i in range(0, len(all_files), BATCH):
                yield f"{path} [{i}:{i + len(all_files[i:i + BATCH])}]", all_files[i:i + BATCH]


def iter_batches(path: str):
    """Yield lists of JsFile, one part-subdir at a time (bounded memory)."""
    for _label, files in iter_labeled_batches(path):
        yield files


def dir_manifest(path: str) -> dict:
    """{full_file_path: original_url} for a part-subdir (from _manifest.json,
    else every *.js with a file:// url). No file contents are read."""
    m = {}
    mpath = os.path.join(path, "_manifest.json")
    if os.path.exists(mpath):
        try:
            with open(mpath, encoding="utf-8") as fh:
                raw = json.load(fh)
            return {os.path.join(path, fn): url for fn, url in raw.items()}
        except Exception:
            pass
    for fn in sorted(os.listdir(path)):
        if fn.endswith(".js"):
            m[os.path.join(path, fn)] = "file://" + os.path.join(path, fn)
    return m


def part_paths(path: str) -> list[str]:
    """The subdirs to analyze, one at a time. Part-dirs if present, else the
    dir itself (flat corpus / arbitrary .js dir)."""
    parts = _part_dirs(path)
    return parts if parts else [path]


def all_urls(base: str) -> set:
    """Every original URL already in the corpus (small; strings only)."""
    out: set = set()
    for p in part_paths(base):
        out.update(dir_manifest(p).values())
    return out


def part_count(path: str) -> int:
    """Number of part-subdirs, or the expected batch count for a flat dir."""
    parts = _part_dirs(path)
    if parts:
        return len(parts)
    try:
        n = sum(1 for fn in os.listdir(path) if fn.endswith(".js"))
    except OSError:
        return 0
    return (n + BATCH - 1) // BATCH


def count(path: str) -> int:
    n = 0
    for d in ([path] + _part_dirs(path)):
        try:
            n += sum(1 for fn in os.listdir(d) if fn.endswith(".js"))
        except OSError:
            pass
    return n


def load(path: str) -> list[JsFile]:
    """Load the WHOLE corpus at once (small corpora / callers that need it all).
    Prefer iter_batches for large ones."""
    out: list[JsFile] = []
    for b in iter_batches(path):
        out.extend(b)
    return out
