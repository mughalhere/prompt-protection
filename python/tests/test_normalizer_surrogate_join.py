"""Stripping an invisible char between surrogate halves leaves a valid pair (found by differential testing).

Oracle: Node 22, src/utils/unicode.ts normalizeUnicode (esbuild bundle) and dist/internal.js normalize,
over strings built from String.fromCharCode(0xd83d) and (0xde00) around U+200B or U+202A.
"""

import pytest

from prompt_protection._js import utf16_len
from prompt_protection.normalizer import normalize
from prompt_protection.unicode import normalize_unicode

HI = "\ud83d"
LO = "\ude00"
ZWSP = "\u200b"
EMOJI = "\U0001f600"

JOIN_CASES = [
    pytest.param(HI + ZWSP + LO, EMOJI, [0, 2], id="zwsp-between-halves"),
    pytest.param("a" + HI + ZWSP + LO + "b", "a" + EMOJI + "b", [0, 1, 3, 4], id="zwsp-between-halves-in-text"),
    pytest.param(HI + ZWSP + ZWSP + LO, EMOJI, [0, 3], id="two-zwsp-between-halves"),
    pytest.param(HI + "\u202a" + LO, EMOJI, [0, 2], id="bidi-mark-between-halves"),
    pytest.param(HI + LO, EMOJI, [0, 1], id="adjacent-split-halves"),
    pytest.param(HI + ZWSP + HI + LO, HI + EMOJI, [0, 2, 3], id="lone-high-then-zwsp-then-pair"),
    pytest.param(LO + ZWSP + HI, LO + HI, [0, 2], id="reversed-halves-stay-lone"),
]

NFKC_ORDER_CASES = [
    pytest.param("\ud835\udc00", "A", "a", [0], id="nfkc-sees-adjacent-halves-as-one-char"),
    pytest.param("\ud835" + ZWSP + "\udc00", "\U0001d400", "\U0001d400", [0, 2], id="nfkc-does-not-rerun-after-strip"),
]


@pytest.mark.parametrize(("text", "expected", "_index_map"), JOIN_CASES)
def test_normalize_unicode_joins_halves_that_a_strip_made_adjacent(
    text: str, expected: str, _index_map: list[int]
) -> None:
    assert normalize_unicode(text) == expected


@pytest.mark.parametrize(("text", "expected", "index_map"), JOIN_CASES)
def test_normalize_joins_halves_and_maps_each_utf16_unit(text: str, expected: str, index_map: list[int]) -> None:
    result = normalize(text)
    assert result.normalized == expected
    assert list(result.index_map) == index_map
    assert len(result.index_map) == utf16_len(expected)


def test_joined_pair_is_one_code_point_in_python() -> None:
    assert len(normalize_unicode(HI + ZWSP + LO)) == 1


@pytest.mark.parametrize(("text", "unicode_form", "normalized", "index_map"), NFKC_ORDER_CASES)
def test_nfkc_runs_on_joined_halves_but_not_after_the_strip(
    text: str, unicode_form: str, normalized: str, index_map: list[int]
) -> None:
    assert normalize_unicode(text) == unicode_form
    result = normalize(text)
    assert result.normalized == normalized
    assert list(result.index_map) == index_map
