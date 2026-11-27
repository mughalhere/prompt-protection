"""URL and base64 obfuscation decoding, ported from src/utils/encoding.ts."""

import binascii
import re

from prompt_protection._js import decode_uri_component, utf16_len, utf16_slice

__all__ = ["decode_obfuscation"]

_BASE64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_PRINTABLE_ASCII = re.compile(rb"[\x20-\x7e]+")
_MAX_DECODE_PASSES = 3
_MAX_DECODED_LENGTH = 50_000


def _try_base64_decode(segment: str) -> str | None:
    """Return the text ``atob`` yields when it is printable ASCII, else None (WHATWG forgiving-base64)."""
    data = segment
    if len(data) % 4 == 0:
        data = data.removesuffix("==") if data.endswith("==") else data.removesuffix("=")
    if len(data) % 4 == 1 or "=" in data:
        return None
    raw = binascii.a2b_base64(data + "=" * (-len(data) % 4))
    if _PRINTABLE_ASCII.fullmatch(raw) is None:
        return None
    return raw.decode("ascii")


def _decode_once(text: str) -> tuple[str, bool]:
    result = _PERCENT.sub(lambda match: decode_uri_component(match.group()), text)
    changed = result != text
    extra = [
        decoded for match in _BASE64.finditer(result) if (decoded := _try_base64_decode(match.group())) is not None
    ]
    if extra:
        result = f"{result} {' '.join(extra)}"
        changed = True
    if utf16_len(result) > _MAX_DECODED_LENGTH:
        result = utf16_slice(result, 0, _MAX_DECODED_LENGTH)
    return result, changed


def decode_obfuscation(text: str) -> str:
    """Decode percent escapes and append decoded base64 segments, for up to three passes. For scoring only."""
    result = text
    for _ in range(_MAX_DECODE_PASSES):
        result, changed = _decode_once(result)
        if not changed:
            break
    return result
