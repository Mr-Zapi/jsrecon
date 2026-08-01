"""Data models for jsrecon."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class JsFile:
    """A single JavaScript source extracted from a Burp item."""
    url: str            # absolute URL the JS was served from (or page URL for inline)
    source: str         # the JavaScript source code
    origin: str         # "response" | "inline"
    host: str = ""
    mimetype: str = ""

    def base_url(self) -> str:
        return self.url


@dataclass
class Endpoint:
    """A discovered endpoint / request candidate found by jsluice."""
    url: str                              # resolved absolute URL (best effort)
    raw_url: str = ""                     # original url string as found in JS
    method: str = "GET"
    query_params: list[str] = field(default_factory=list)
    body_params: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    detect_type: str = ""                 # jsluice "type": fetch, $.ajax, stringLiteral...
    found_in: list[str] = field(default_factory=list)  # JS file URLs it was found in
    host: str = ""
    scheme: str = "https"
    path: str = ""
    # enrichment
    category: str = "page"                # "api" | "page" | "static"
    is_static: bool = False
    is_api: bool = False
    tags: list[str] = field(default_factory=list)   # gf classes: redirect, lfi, rce...
    path_template: str = ""               # path with id-like segments -> {id}
    count: int = 1                        # how many raw endpoints collapsed here

    @property
    def has_param(self) -> bool:
        return bool(self.query_params or self.body_params)

    def key(self) -> str:
        return f"{self.method.upper()} {self.url}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["has_param"] = self.has_param
        return d

    _FIELDS = ("url", "raw_url", "method", "query_params", "body_params", "headers",
               "content_type", "detect_type", "found_in", "host", "scheme", "path",
               "category", "is_static", "is_api", "tags", "path_template", "count")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Endpoint":
        return cls(**{k: d[k] for k in cls._FIELDS if k in d})


@dataclass
class Finding:
    """A SAST finding (secret from jsluice, or gf-flagged endpoint/source)."""
    kind: str                             # e.g. AWSAccessKey, gf:redirect
    severity: str = "info"                # info|low|medium|high
    source: str = "jsluice-secrets"       # jsluice-secrets | gf
    evidence: str = ""                    # the matched value / snippet
    location: str = ""                    # JS file url or endpoint url
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def key(self) -> str:
        return f"{self.kind}:{self.evidence}:{self.location}"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        fields = ("kind", "severity", "source", "evidence", "location", "extra")
        return cls(**{k: d[k] for k in fields if k in d})
