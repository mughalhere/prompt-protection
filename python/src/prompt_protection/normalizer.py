"""Normalised text and the map back to the original, ported from src/normalizer.ts."""

from bisect import bisect_left
from dataclasses import dataclass

from prompt_protection._js import code_units, utf16_len
from prompt_protection.encoding import decode_obfuscation
from prompt_protection.unicode import apply_homoglyphs, normalize_unicode

__all__ = ["NormalizeResult", "normalize"]


@dataclass(frozen=True, slots=True)
class NormalizeResult:
    normalized: str
    index_map: list[int]


def _build_index_map(original: str, normalized: str) -> list[int]:
    """Return ``buildIndexMap`` from src/normalizer.ts in UTF-16 units, in O((n + m) log n) instead of O(n * m)."""
    lowered = code_units(original.lower())
    targets = code_units(normalized)
    last = utf16_len(original) - 1
    positions: dict[int, list[int]] = {}
    for index, unit in enumerate(lowered):
        positions.setdefault(unit, []).append(index)

    result: list[int] = []
    cursor = 0
    for done, unit in enumerate(targets):
        if cursor >= len(lowered):
            result.extend([max(0, last)] * (len(targets) - done))
            break
        candidates = positions.get(unit, [])
        slot = bisect_left(candidates, cursor)
        if slot < len(candidates):
            result.append(candidates[slot])
            cursor = candidates[slot] + 1
        else:
            result.append(max(0, min(cursor, last)))
    return result


def normalize(text: str) -> NormalizeResult:
    """Normalise ``text`` for matching: Unicode clean-up, decode, homoglyphs, then lowercase."""
    normalized = apply_homoglyphs(decode_obfuscation(normalize_unicode(text))).lower()
    return NormalizeResult(normalized, _build_index_map(text, normalized))
