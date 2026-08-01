"""Crash-proof URL parsing.

urllib's urlsplit raises ValueError ("Invalid IPv6 URL") when a string pulled
out of a JS bundle contains an unbalanced '[' (webpack chunk names, template
literals, minified junk). One bad string used to kill a whole recon job, so all
URL parsing on untrusted input goes through these wrappers.
"""
from __future__ import annotations

from urllib.parse import SplitResult
from urllib.parse import urljoin as _urljoin
from urllib.parse import urlsplit as _urlsplit

_EMPTY = SplitResult("", "", "", "", "")


def safe_urlsplit(url, scheme: str = "", allow_fragments: bool = True) -> SplitResult:
    try:
        return _urlsplit(url, scheme, allow_fragments)
    except ValueError:
        return _EMPTY


def safe_urljoin(base, url, allow_fragments: bool = True) -> str:
    try:
        return _urljoin(base, url, allow_fragments)
    except ValueError:
        return url or base or ""
