"""Word and char shingles ported from src/utils/shingle.ts. Char windows are 24 UTF-16 code units wide."""

import math
import re
from dataclasses import dataclass

from prompt_protection._js import code_units
from prompt_protection._result import JsResult
from prompt_protection.hash import fnv1a32

__all__ = [
    "CHAR_SHINGLE",
    "CHAR_STRIDE",
    "WORD_SHINGLE",
    "Containment",
    "ShingleSet",
    "build_shingles",
    "containment",
    "tokenize",
]

WORD_SHINGLE = 6
CHAR_SHINGLE = 24
CHAR_STRIDE = 4

_TOKEN_RE = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True, slots=True)
class ShingleSet(JsResult):
    words: frozenset[int]
    chars: frozenset[int]
    word_count: int


@dataclass(frozen=True, slots=True)
class Containment(JsResult):
    """``word`` and ``char`` are the fractions of needle shingles found in the hay, ``matched`` the hit count."""

    word: float
    char: float
    matched: int


_EMPTY = Containment(0.0, 0.0, 0)


def tokenize(normalized: str) -> list[str]:
    """Split already-normalized text into runs of ``[a-z0-9]``."""
    return _TOKEN_RE.findall(normalized)


def _stride(char_stride: float) -> float:
    """Return JS ``Math.max(1, Math.floor(x))``. NaN and +infinity stay non-finite, as in JS."""
    if math.isnan(char_stride) or char_stride == math.inf:
        return math.inf
    return 1 if char_stride == -math.inf else max(1, math.floor(char_stride))


def _char_hashes(normalized: str, char_stride: float) -> frozenset[int]:
    if not normalized:
        return frozenset()
    units = normalized if normalized.isascii() else "".join(map(chr, code_units(normalized)))
    if len(units) < CHAR_SHINGLE:
        return frozenset({fnv1a32(normalized)})
    stride = _stride(char_stride)
    last_start = len(units) - CHAR_SHINGLE
    starts = range(0, last_start + 1, int(stride)) if stride <= last_start else (0,)
    return frozenset(fnv1a32(units[i : i + CHAR_SHINGLE]) for i in starts)


def _word_hashes(tokens: list[str]) -> frozenset[int]:
    if 0 < len(tokens) < WORD_SHINGLE:
        return frozenset({fnv1a32(" ".join(tokens))})
    return frozenset(fnv1a32(" ".join(tokens[i : i + WORD_SHINGLE])) for i in range(len(tokens) - WORD_SHINGLE + 1))


def build_shingles(normalized: str, char_stride: float = CHAR_STRIDE) -> ShingleSet:
    """Hash overlapping word and char windows.

    An input shorter than a window yields one shingle of the whole input. ``char_stride`` is
    floored and clamped to at least 1. Use 1 for the hay side of a containment.
    """
    tokens = tokenize(normalized)
    return ShingleSet(_word_hashes(tokens), _char_hashes(normalized, char_stride), len(tokens))


def _fraction(needle: frozenset[int], hay: frozenset[int]) -> tuple[float, int]:
    if not needle:
        return 0.0, 0
    hits = len(needle & hay)
    return hits / len(needle), hits


def containment(needle: str | ShingleSet, hay: str | ShingleSet) -> Containment:
    """Return the fraction of ``needle`` shingles present in ``hay``. A string hay is indexed at every offset."""
    n = build_shingles(needle) if isinstance(needle, str) else needle
    if not n.words and not n.chars:
        return _EMPTY
    h = build_shingles(hay, 1) if isinstance(hay, str) else hay
    word, word_hits = _fraction(n.words, h.words)
    char, char_hits = _fraction(n.chars, h.chars)
    return Containment(word, char, word_hits + char_hits)
