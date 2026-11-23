"""Canonical JSON (RFC 8785 subset) and content digests, ported from ``src/utils/canonical.ts``."""

import hashlib
import math
import re
from typing import Literal

from prompt_protection._js import js_number_str

__all__ = [
    "CanonicalJsonError",
    "CanonicalJsonErrorCode",
    "canonical_json",
    "digest",
    "digest_sync_weak",
    "fnv1a64_hex",
]

CanonicalJsonErrorCode = Literal["non-finite", "bigint", "cycle", "depth", "unsupported"]

_MAX_DEPTH = 64
_FNV_OFFSET = 0xCBF29CE484222325
_FNV_PRIME = 0x100000001B3
_MASK_64 = 0xFFFFFFFFFFFFFFFF

_SURROGATE_CLASS = "[" + chr(0xD800) + "-" + chr(0xDFFF) + "]"
_SURROGATE = re.compile(_SURROGATE_CLASS)
_NEEDS_ESCAPE = re.compile(r'[\x00-\x1f"\\]|' + _SURROGATE_CLASS)
_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalJsonError(TypeError):
    """Raised for a value that has no faithful canonical JSON form. ``code`` names the reason."""

    def __init__(self, code: CanonicalJsonErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


def _escape_char(match: re.Match[str]) -> str:
    char = match.group()
    return _SHORT_ESCAPES.get(char) or f"\\u{ord(char):04x}"


def _utf16_pairs_joined(text: str) -> str:
    """Join adjacent surrogate code points into one code point, as a JS string already holds them."""
    if _SURROGATE.search(text) is None:
        return text
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _json_string(text: str) -> str:
    """Return JS ``JSON.stringify(text)``: control characters and lone surrogates escaped, the rest raw."""
    return '"' + _NEEDS_ESCAPE.sub(_escape_char, _utf16_pairs_joined(text)) + '"'


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _number(value: int | float) -> str:
    try:
        number = float(value)
    except OverflowError:
        raise CanonicalJsonError("non-finite", "integer too large for a finite number has no JSON form") from None
    if not math.isfinite(number):
        raise CanonicalJsonError("non-finite", f"{js_number_str(number)} has no JSON form")
    return js_number_str(number)


def _serialize(value: object, depth: int, seen: set[int]) -> str:
    if value is not None and not isinstance(value, (str, int, float, type)):
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            value = to_dict()
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _json_string(value)
    if isinstance(value, (int, float)):
        return _number(value)

    if depth > _MAX_DEPTH:
        raise CanonicalJsonError("depth", f"nesting deeper than {_MAX_DEPTH}")
    if id(value) in seen:
        raise CanonicalJsonError("cycle", "circular reference")
    if not isinstance(value, (dict, list, tuple)):
        raise CanonicalJsonError("unsupported", f"{type(value).__name__} has no to_dict")
    seen.add(id(value))
    try:
        if isinstance(value, dict):
            return _serialize_dict(value, depth, seen)
        return "[" + ",".join(_serialize(item, depth + 1, seen) for item in value) + "]"
    finally:
        seen.discard(id(value))


def _serialize_dict(value: dict[object, object], depth: int, seen: set[int]) -> str:
    keys: list[str] = []
    for key in value:
        if not isinstance(key, str):
            raise CanonicalJsonError("unsupported", f"object key of type {type(key).__name__} is not a string")
        keys.append(key)
    keys.sort(key=_utf16_key)
    parts = [f"{_json_string(key)}:{_serialize(value[key], depth + 1, seen)}" for key in keys]
    return "{" + ",".join(parts) + "}"


def canonical_json(value: object) -> str:
    """Return deterministic JSON: keys sorted by UTF-16 code unit, ``to_dict`` honoured, ``-0.0`` as ``0``.

    Raises ``CanonicalJsonError`` for non-finite numbers, cycles, nesting over 64 and
    values with no JSON form (set, frozenset, bytes, a non-str key, a class without ``to_dict``).
    """
    return _serialize(value, 0, set())


def _utf8(text: str) -> bytes:
    """Encode like ``TextEncoder``: a lone surrogate becomes U+FFFD instead of raising."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace").encode("utf-8")


def fnv1a64_hex(text: str) -> str:
    """Return FNV-1a 64-bit over the UTF-8 bytes of ``text`` as 16 lowercase hex digits."""
    state = _FNV_OFFSET
    for byte in _utf8(text):
        state = ((state ^ byte) * _FNV_PRIME) & _MASK_64
    return f"{state:016x}"


def _text_of(value: object) -> str:
    return value if isinstance(value, str) else canonical_json(value)


def digest(value: object) -> str:
    """Return ``sha256:<hex>`` of a string as is, or of any other value through ``canonical_json``."""
    return f"sha256:{hashlib.sha256(_utf8(_text_of(value))).hexdigest()}"


def digest_sync_weak(value: object) -> str:
    """Return ``fnv1a64:<hex>`` for counting and dedupe. It is not an integrity check."""
    return f"fnv1a64:{fnv1a64_hex(_text_of(value))}"
