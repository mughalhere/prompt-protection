"""JavaScript string and number semantics that Python lacks (UTF-16 offsets, Math.round, Number#toString)."""

import math
import re
import struct
from decimal import Decimal

__all__ = [
    "JS_DOT",
    "JS_WHITESPACE",
    "code_units",
    "cp_to_utf16_offset",
    "decode_uri_component",
    "js_number_str",
    "js_round",
    "js_trim",
    "utf16_len",
    "utf16_slice",
    "utf16_to_cp_offset",
]

# The 25 code points that JS \s matches, written with escapes so the source stays ASCII.
JS_WHITESPACE = r"[\t\n\x0b\x0c\r\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]"
JS_DOT = r"[^\n\r\u2028\u2029]"

_HEX_PAIR = "[0-9A-Fa-f]{2}"
_BAD_ESCAPE = re.compile(f"%(?!{_HEX_PAIR})")
_ESCAPE_RUN = re.compile(f"(?:%{_HEX_PAIR})+")
_MAX_EXACT_HALF = 2**52


def _encode(text: str) -> bytes:
    return text.encode("utf-16-le", "surrogatepass")


def utf16_len(text: str) -> int:
    """Return JS ``text.length``: the number of UTF-16 code units."""
    return len(_encode(text)) // 2


def code_units(text: str) -> list[int]:
    """Return JS ``charCodeAt(i)`` for every index, lone surrogates included."""
    data = _encode(text)
    return list(struct.unpack(f"<{len(data) // 2}H", data))


def _clamp_index(index: int, length: int) -> int:
    return max(length + index, 0) if index < 0 else min(index, length)


def utf16_slice(text: str, start: int, end: int | None = None) -> str:
    """Return JS ``text.slice(start, end)`` over UTF-16 code units, including negative indexes."""
    data = _encode(text)
    length = len(data) // 2
    lo = _clamp_index(start, length)
    hi = length if end is None else _clamp_index(end, length)
    if lo >= hi:
        return ""
    return data[2 * lo : 2 * hi].decode("utf-16-le", "surrogatepass")


def cp_to_utf16_offset(text: str, cp_offset: int) -> int:
    """Return the UTF-16 offset of the code point at ``cp_offset``, clamped to the text."""
    cp_offset = max(cp_offset, 0)
    if text.isascii():
        return min(cp_offset, len(text))
    return utf16_len(text[:cp_offset])


def utf16_to_cp_offset(text: str, unit_offset: int) -> int:
    """Return the index of the code point that contains UTF-16 offset ``unit_offset``, clamped to the text."""
    unit_offset = max(unit_offset, 0)
    if text.isascii():
        return min(unit_offset, len(text))
    units = 0
    for index, char in enumerate(text):
        units += 2 if ord(char) > 0xFFFF else 1
        if units > unit_offset:
            return index
    return len(text)


def js_round(value: float) -> int:
    """Return JS ``Math.round(value)``: ties go toward positive infinity. Raises on NaN and infinity."""
    floor = math.floor(value)
    if abs(value) >= _MAX_EXACT_HALF:
        return floor
    return floor + 1 if value >= floor + 0.5 else floor


_JS_TRIM_CHARS = "".join(
    map(
        chr,
        (9, 10, 11, 12, 13, 32, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF),
    )
)


def js_trim(text: str) -> str:
    """Return JS ``text.trim()``: U+FEFF is stripped, U+0085 and U+001C are kept, unlike ``str.strip``."""
    return text.strip(_JS_TRIM_CHARS)


def js_number_str(value: float) -> str:
    """Return JS ``String(value)`` for a number, following the ECMAScript Number::toString layout."""
    number = float(value)
    if math.isnan(number):
        return "NaN"
    if math.isinf(number):
        return "Infinity" if number > 0 else "-Infinity"
    if number == 0:
        return "0"
    sign, digit_tuple, exponent = Decimal(repr(abs(number))).as_tuple()
    assert isinstance(exponent, int)
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    exponent += len(digit_tuple) - len(digits)
    count = len(digits)
    point = count + exponent
    prefix = "-" if number < 0 else ""
    if count <= point <= 21:
        body = digits + "0" * (point - count)
    elif 0 < point <= 21:
        body = f"{digits[:point]}.{digits[point:]}"
    elif -6 < point <= 0:
        body = f"0.{'0' * -point}{digits}"
    else:
        mantissa = digits if count == 1 else f"{digits[0]}.{digits[1:]}"
        body = f"{mantissa}e{'+' if point > 0 else '-'}{abs(point - 1)}"
    return prefix + body


def decode_uri_component(text: str) -> str:
    """Return JS ``decodeURIComponent(text)``, or ``text`` unchanged where JS would throw ``URIError``."""
    if _BAD_ESCAPE.search(text):
        return text

    def decode_run(match: re.Match[str]) -> str:
        return bytes.fromhex(match.group().replace("%", "")).decode("utf-8")

    try:
        return _ESCAPE_RUN.sub(decode_run, text)
    except UnicodeDecodeError:
        return text
