"""A small logical filter language for endpoints.

Examples:
    domain=*kuper.ru && method=GET
    (category=api || has_param) && !domain=*sentry*
    tag=redirect || tag=lfi
    path~/admin && method!=GET

Fields: domain/host, path, url, method, type, category, tag, param, scheme
Boolean flags: has_param, api, static
Operators: =  != ~ (contains)   combine with && || ! ( )
Values support * wildcards.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .models import Endpoint

_TOKEN_RE = re.compile(r"""
    \s*(?:
      (?P<lparen>\() |
      (?P<rparen>\)) |
      (?P<and>&&) |
      (?P<or>\|\|) |
      (?P<not>!(?!=)) |
      (?P<op>!=|=|~) |
      (?P<word>[^\s()&|!~=]+)
    )
""", re.VERBOSE)


def _tokenize(s: str):
    pos = 0
    toks = []
    while pos < len(s):
        m = _TOKEN_RE.match(s, pos)
        if not m or m.end() == pos:
            if s[pos].isspace():
                pos += 1
                continue
            raise ValueError(f"bad token at {pos}: {s[pos:pos+10]!r}")
        pos = m.end()
        kind = m.lastgroup
        toks.append((kind, m.group(kind)))
    toks.append(("end", ""))
    return toks


def _wild(value: str) -> Callable[[str], bool]:
    if "*" in value:
        rx = re.compile("^" + re.escape(value).replace(r"\*", ".*") + "$", re.IGNORECASE)
        return lambda x: bool(rx.match(x or ""))
    v = value.lower()
    return lambda x: (x or "").lower() == v


_FLAGS = {"has_param", "api", "static"}


def _field_values(ep: Endpoint, field: str) -> list[str]:
    f = field.lower()
    if f in ("domain", "host"):
        return [ep.host]
    if f == "path":
        return [ep.path]
    if f == "url":
        return [ep.url]
    if f == "method":
        return [ep.method]
    if f == "type":
        return [ep.detect_type]
    if f == "category":
        return [ep.category]
    if f == "scheme":
        return [ep.scheme]
    if f == "tag":
        return ep.tags or [""]
    if f == "param":
        return (ep.query_params + ep.body_params) or [""]
    return [""]


@dataclass
class _Cmp:
    field: str
    op: str
    value: str

    def eval(self, ep: Endpoint) -> bool:
        vals = _field_values(ep, self.field)
        if self.op == "~":
            needle = self.value.lower()
            return any(needle in (v or "").lower() for v in vals)
        match = _wild(self.value)
        res = any(match(v) for v in vals)
        return res if self.op == "=" else not res


@dataclass
class _Flag:
    name: str

    def eval(self, ep: Endpoint) -> bool:
        if self.name == "has_param":
            return ep.has_param
        if self.name == "api":
            return ep.is_api
        if self.name == "static":
            return ep.is_static
        return False


class _Parser:
    def __init__(self, toks):
        self.toks = toks
        self.i = 0

    def peek(self):
        return self.toks[self.i]

    def next(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def parse(self):
        node = self._or()
        if self.peek()[0] != "end":
            raise ValueError(f"unexpected trailing token {self.peek()[1]!r}")
        return node

    def _or(self):
        left = self._and()
        while self.peek()[0] == "or":
            self.next()
            right = self._and()
            l, r = left, right
            left = lambda ep, l=l, r=r: l(ep) or r(ep)
        return left

    def _and(self):
        left = self._unary()
        while self.peek()[0] == "and":
            self.next()
            right = self._unary()
            l, r = left, right
            left = lambda ep, l=l, r=r: l(ep) and r(ep)
        return left

    def _unary(self):
        kind, val = self.peek()
        if kind == "not":
            self.next()
            inner = self._unary()
            return lambda ep, inner=inner: not inner(ep)
        if kind == "lparen":
            self.next()
            node = self._or()
            if self.peek()[0] != "rparen":
                raise ValueError("missing )")
            self.next()
            return node
        return self._cmp()

    def _cmp(self):
        kind, val = self.next()
        if kind != "word":
            raise ValueError(f"expected field, got {val!r}")
        field = val
        nxt = self.peek()
        if nxt[0] == "op":
            self.next()
            vk, vv = self.next()
            if vk != "word":
                raise ValueError("expected value after operator")
            cmp = _Cmp(field, nxt[1], vv)
            return lambda ep, c=cmp: c.eval(ep)
        # bare word -> flag
        if field.lower() in _FLAGS:
            flag = _Flag(field.lower())
            return lambda ep, f=flag: f.eval(ep)
        raise ValueError(f"unknown flag or missing operator: {field!r}")


def compile_filter(expr: str) -> Callable[[Endpoint], bool]:
    """Compile a filter expression into a predicate. Empty -> match all."""
    expr = (expr or "").strip()
    if not expr:
        return lambda ep: True
    toks = _tokenize(expr)
    return _Parser(toks).parse()


def apply_filter(endpoints, expr: str):
    pred = compile_filter(expr)
    return [ep for ep in endpoints if pred(ep)]
