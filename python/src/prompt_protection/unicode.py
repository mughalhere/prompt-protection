"""Unicode normalisation and homoglyph folding, ported from src/utils/unicode.ts."""

import re
import unicodedata

from prompt_protection._js import JS_WHITESPACE

__all__ = ["apply_homoglyphs", "normalize_unicode"]

_HOMOGLYPHS = {
    0x30: "o",
    0x31: "i",
    0x33: "e",
    0x34: "a",
    0x35: "s",
    0x36: "g",
    0x37: "t",
    0x38: "b",
    0x40: "a",
    0x24: "s",
    0x21: "i",
    0x0430: "a",
    0x0435: "e",
    0x043E: "o",
    0x0440: "r",
    0x0441: "c",
    0x0445: "x",
    0x0456: "i",
    0x0399: "i",
    0x03BF: "o",
}

_ZERO_WIDTH = (
    0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x180E, 0x00AD, 0x034F,
    0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0,
)  # fmt: skip
_TAGS = range(0xE0001, 0xE0080)
_BIDI = (*range(0x202A, 0x202F), *range(0x2066, 0x206A))
_FULLWIDTH_OFFSET = 0xFEE0

_CLEAN: dict[int, str | None] = {
    **dict.fromkeys((*_ZERO_WIDTH, *_TAGS, *_BIDI)),
    **{code: chr(code - _FULLWIDTH_OFFSET) for code in range(0xFF01, 0xFF5F)},
    0x3000: " ",
}
_WHITESPACE_RUN = re.compile(f"{JS_WHITESPACE}+")
_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _join_surrogate_pairs(text: str) -> str:
    """Return the str a JS string of the same UTF-16 units would be: adjacent high and low surrogates become one."""
    if _SURROGATE.search(text) is None:
        return text
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def normalize_unicode(text: str) -> str:
    """NFKC, strip invisible, bidi and tag characters, fold fullwidth, collapse JS whitespace. No homoglyphs."""
    cleaned = _join_surrogate_pairs(unicodedata.normalize("NFKC", _join_surrogate_pairs(text)).translate(_CLEAN))
    return _WHITESPACE_RUN.sub(" ", cleaned).strip(" ")


def apply_homoglyphs(text: str) -> str:
    """Replace look-alike digits, symbols and Cyrillic or Greek letters. Run it after URL and base64 decoding."""
    return text.translate(_HOMOGLYPHS)
