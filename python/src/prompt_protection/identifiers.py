"""Identifier extraction ported from src/utils/identifiers.ts, with every offset in UTF-16 code units."""

import re
from dataclasses import dataclass

from prompt_protection._js import JS_WHITESPACE, code_units, js_trim
from prompt_protection._result import JsResult

__all__ = ["Identifier", "extract_identifiers"]

_WS = JS_WHITESPACE[1:-1]
_FLAGS = re.ASCII

_URL_RE = re.compile(r"\bhttps?://[^" + _WS + r"<>\"'`()\[\]{}]+", _FLAGS | re.IGNORECASE)
_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", _FLAGS)
_IPV4_RE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", _FLAGS)
_HOST_RE = re.compile(r"(?<![A-Za-z0-9.@/-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![A-Za-z0-9-])", _FLAGS)
_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9._~-])(?:~/[^" + _WS + r"\"'<>`]+|\.{1,2}/[^" + _WS + r"\"'<>`]+"
    r"|/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+|[A-Za-z]:\\[^" + _WS + r"\"'<>`]+)",
    _FLAGS,
)
_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])", _FLAGS)
_PHONE_RE = re.compile(r"(?<![0-9+])\+?[0-9][0-9" + _WS + r"().-]{7,18}[0-9](?![0-9])", _FLAGS)

_TRAILING_PUNCT_RE = re.compile(r"(?<![.,;:!?'\"`)\]}>])[.,;:!?'\"`)\]}>]+\Z")
_AUTHORITY_END_RE = re.compile(r"[/?#]")
_PORT_RE = re.compile(r":[0-9]+\Z")

_FILE_EXT_TLDS = frozenset(
    "js ts tsx jsx mjs cjs py md txt json yml yaml html css csv png jpg jpeg gif svg pdf exe sh env lock toml "
    "xml zip tar gz log test spec config min map rs go java".split()
)


@dataclass(frozen=True, slots=True)
class Identifier(JsResult):
    """``value`` is the canonical form, ``raw`` the text as written and ``index`` a UTF-16 offset of ``raw``."""

    kind: str
    value: str
    raw: str
    index: int


def _units(text: str) -> str:
    """Return ``text`` with one ``str`` character per UTF-16 code unit, so ``str`` offsets are JS offsets."""
    return text if text.isascii() else "".join(map(chr, code_units(text)))


def _joined(units: str) -> str:
    """Join adjacent surrogate characters back into code points. A lone surrogate stays as it is."""
    if units.isascii():
        return units
    return units.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _strip_trailing(raw: str) -> str:
    return _TRAILING_PUNCT_RE.sub("", raw, count=1)


def _authority(after_scheme: str) -> str:
    return _AUTHORITY_END_RE.split(after_scheme, maxsplit=1)[0]


def _host_of_url(url: str) -> str | None:
    authority = _authority(url[url.index("//") + 2 :])
    host = _PORT_RE.sub("", authority[authority.rfind("@") + 1 :], count=1)
    return _joined(host).lower() if host else None


def _valid_ipv4(raw: str) -> bool:
    return all(int(octet) <= 255 for octet in raw.split("."))


def _phone_digits(raw: str) -> str | None:
    digits = "".join(char for char in raw if "0" <= char <= "9")
    if not 10 <= len(digits) <= 15:
        return None
    return f"+{digits}" if raw.startswith("+") else digits


def _has_letter_and_digit(raw: str) -> bool:
    return any("A" <= c <= "Z" or "a" <= c <= "z" for c in raw) and any("0" <= c <= "9" for c in raw)


def extract_identifiers(text: str) -> list[Identifier]:
    """Extract URLs, hosts, emails, paths, IPv4s, opaque tokens and phone numbers, ordered by ``(index, kind)``.

    Kinds are matched in priority order and never overlap, except that a URL also emits its host.
    """
    units = _units(text)
    out: list[Identifier] = []
    taken: list[tuple[int, int]] = []

    def free(start: int, raw: str) -> bool:
        end = start + len(raw)
        return not any(start < t_end and end > t_start for t_start, t_end in taken)

    def claim(kind: str, raw: str, index: int, value: str) -> None:
        taken.append((index, index + len(raw)))
        out.append(Identifier(kind, value, _joined(raw), index))

    for m in _URL_RE.finditer(units):
        raw = _strip_trailing(m.group())
        host = _host_of_url(raw)
        if host is None:
            continue
        scheme_end = raw.index("//") + 2
        authority_end = scheme_end + len(_authority(raw[scheme_end:]))
        value = _joined(raw[:authority_end]).lower() + _joined(raw[authority_end:])
        claim("url", raw, m.start(), value)
        out.append(Identifier("host", host, host, m.start() + scheme_end))

    for m in _EMAIL_RE.finditer(units):
        raw = _strip_trailing(m.group())
        if free(m.start(), raw):
            claim("email", raw, m.start(), raw.lower())

    for m in _PATH_RE.finditer(units):
        raw = _strip_trailing(m.group())
        if len(raw) >= 2 and free(m.start(), raw):
            claim("path", raw, m.start(), _joined(raw))

    for m in _IPV4_RE.finditer(units):
        raw = m.group()
        if _valid_ipv4(raw) and free(m.start(), raw):
            claim("ipv4", raw, m.start(), raw)

    for m in _PHONE_RE.finditer(units):
        raw = js_trim(m.group())
        digits = _phone_digits(raw)
        if digits is not None and free(m.start(), raw):
            claim("phone", raw, m.start(), digits)

    for m in _HOST_RE.finditer(units):
        raw = m.group()
        tld = raw[raw.rfind(".") + 1 :].lower()
        if tld not in _FILE_EXT_TLDS and free(m.start(), raw):
            claim("host", raw, m.start(), raw.lower())

    for m in _TOKEN_RE.finditer(units):
        raw = m.group()
        if _has_letter_and_digit(raw) and free(m.start(), raw):
            claim("token", raw, m.start(), raw)

    out.sort(key=lambda found: (found.index, found.kind))
    return out
