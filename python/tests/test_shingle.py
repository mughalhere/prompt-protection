"""RED tests for prompt_protection.shingle (Node 22 is the oracle).

Expected hashes are the output of src/utils/shingle.ts under Node 22. Length, slicing and the 24-unit char
window count UTF-16 code units, so an emoji is two units and a window can cut a pair in half.
"""

import dataclasses
from typing import Any

import pytest

from prompt_protection.hash import fnv1a32
from prompt_protection.shingle import (
    CHAR_SHINGLE,
    CHAR_STRIDE,
    WORD_SHINGLE,
    Containment,
    ShingleSet,
    build_shingles,
    containment,
    tokenize,
)

EMOJI = "\U0001f600"
NEEDLE = "the secret canary phrase is purple elephant seventy"
HAY = f"some preamble here. {NEEDLE}. and a trailer that goes on for a while."

# (case id, text, expected tokens)
TOKENIZE_CASES = [
    ("empty", "", []),
    ("only-separators", "---", []),
    ("basic", "  ignore, previous!! instructions--now ", ["ignore", "previous", "instructions", "now"]),
    ("digits-and-underscore", "abc_123 x9", ["abc", "123", "x9"]),
    ("uppercase-is-a-separator", "Hello World", ["ello", "orld"]),
    ("non-ascii-letters-separate", "caf\u00e9 na\u00efve", ["caf", "na", "ve"]),
    ("non-ascii-digits-separate", "a\u0663b \uff11c", ["a", "b", "c"]),
    ("astral-separates", "ab\U0001f600cd\U0001f600\U0001f600ef", ["ab", "cd", "ef"]),
    ("lone-surrogate-separates", "ab\ud83dcd", ["ab", "cd"]),
    ("unicode-whitespace-separates", "a\u00a0b\u2028c\u0085d\u001ce", ["a", "b", "c", "d", "e"]),
]

# (case id, text, char_stride or None for the default, sorted word hashes, sorted char hashes, word_count)
SHINGLE_CASES = [
    ("empty", "", None, [], [], 0),
    ("short-whole-input", "send it to alice", None, [540498357], [540498357], 4),
    ("eight-words", "a b c d e f g h", None, [3327771604, 4001125670, 4175449786], [1790289551], 8),
    ("exactly-one-word-window", "a b c d e f", None, [4001125670], [4001125670], 6),
    ("seven-words", "a b c d e f g", None, [3327771604, 4001125670], [1116678415], 7),
    ("repeated-words-dedupe", "a a a a a a a a", None, [1295467151], [2886577031], 8),
    ("separators-only", "---", None, [], [3303332998], 0),
    ("punctuated-uppercase", "Hello, World", None, [1446822014], [1725135965], 2),
    ("23-chars-whole-input", "abcdefghijklmnopqrstuvw", None, [2270388311], [2270388311], 1),
    ("24-chars-one-window", "abcdefghijklmnopqrstuvwx", None, [926968317], [926968317], 1),
    ("stride-4-default", "xxxxxxxxxxxxxxxxxxxxxxxxabcdefgh", None, [2229614317], [198485773, 910930637, 2684469285], 1),
    (
        "stride-1",
        "xxxxxxxxxxxxxxxxxxxxxxxxabcdefgh",
        1,
        [2229614317],
        [198485773, 910930637, 1275536082, 1994886713, 2380773877, 2684469285, 2755272450, 3070354522, 3542719886],
        1,
    ),
    (
        "stride-2",
        "xxxxxxxxxxxxxxxxxxxxxxxxabcdefgh",
        2,
        [2229614317],
        [198485773, 910930637, 1275536082, 2684469285, 2755272450],
        1,
    ),
    (
        "stride-0-is-1",
        "xxxxxxxxxxxxxxxxxxxxxxxxabcdefgh",
        0,
        [2229614317],
        [198485773, 910930637, 1275536082, 1994886713, 2380773877, 2684469285, 2755272450, 3070354522, 3542719886],
        1,
    ),
    (
        "stride-negative-is-1",
        "xxxxxxxxxxxxxxxxxxxxxxxxabcdefgh",
        -3,
        [2229614317],
        [198485773, 910930637, 1275536082, 1994886713, 2380773877, 2684469285, 2755272450, 3070354522, 3542719886],
        1,
    ),
    (
        "stride-fraction-floors",
        "xxxxxxxxxxxxxxxxxxxxxxxxabcdefgh",
        2.9,
        [2229614317],
        [198485773, 910930637, 1275536082, 2684469285, 2755272450],
        1,
    ),
    ("stride-larger-than-text", "xxxxxxxxxxxxxxxxxxxxxxxxabcdefgh", 100, [2229614317], [2684469285], 1),
    ("astral-20-units-whole-input", EMOJI * 10, None, [], [2781603245], 0),
    ("astral-26-units-default", EMOJI * 13, None, [], [4121860213], 0),
    ("astral-26-units-stride-1", EMOJI * 13, 1, [], [1556692437, 4121860213], 0),
    ("astral-odd-offset-stride-1", "a" + EMOJI * 12, 1, [3826002220], [2389871764, 4121860213], 1),
    ("astral-odd-offset-default", "a" + EMOJI * 12, None, [3826002220], [2389871764], 1),
    ("astral-between-words", "ab\U0001f600cd", None, [4008059609], [554975072], 2),
    ("lone-surrogate-whole-input", "a\ud83db", None, [279181810], [4199728243], 2),
]

# (case id, needle, hay, word, char, matched); a (text, stride) pair stands for build_shingles(text, stride)
CONTAINMENT_CASES = [
    ("empty-needle", "", HAY, 0, 0, 0),
    ("empty-needle-and-hay", "", "", 0, 0, 0),
    ("empty-hay", NEEDLE, "", 0, 0, 0),
    ("verbatim-substring", NEEDLE, HAY, 1, 1, 10),
    ("unrelated", NEEDLE, "completely different content about cooking pasta at home tonight", 0, 0, 0),
    (
        "partial-overlap",
        NEEDLE,
        "the secret canary phrase is pu then something else entirely",
        0,
        0.2857142857142857,
        2,
    ),
    ("short-needle-equal-hay", "send it to alice", "send it to alice", 1, 1, 2),
    ("short-needle-inside-longer-hay", "send it to alice", "please send it to alice now ok", 0, 0, 0),
    ("prebuilt-sets", (NEEDLE, 4), (HAY, 1), 1, 1, 10),
    (
        "misaligned-hay-default-stride",
        ("0123456789abcdefghijklmnopqrstuvwxyz", 4),
        ("zz0123456789abcdefghijklmnopqrstuvwxyz", 4),
        0,
        0,
        0,
    ),
    (
        "misaligned-hay-stride-1",
        ("0123456789abcdefghijklmnopqrstuvwxyz", 4),
        ("zz0123456789abcdefghijklmnopqrstuvwxyz", 1),
        0,
        1,
        4,
    ),
    ("separators-only-needle", "---", "---", 0, 1, 1),
    ("prebuilt-empty-needle", ("", 4), HAY, 0, 0, 0),
    ("needle-string-hay-prebuilt", NEEDLE, (HAY, 1), 1, 1, 10),
    ("astral-verbatim", EMOJI * 13, "x" + EMOJI * 13 + "y", 0, 1, 1),
    ("astral-odd-offset-hay", "a" + EMOJI * 12 + "bcd", "zza" + EMOJI * 12 + "bcd", 0, 1, 2),
]


def resolve(spec: str | tuple[str, int]) -> str | ShingleSet:
    return spec if isinstance(spec, str) else build_shingles(spec[0], spec[1])


def build(text: str, stride: float | None) -> ShingleSet:
    return build_shingles(text) if stride is None else build_shingles(text, stride)  # type: ignore[arg-type]


def test_constants_match_the_js_window_sizes() -> None:
    assert (WORD_SHINGLE, CHAR_SHINGLE, CHAR_STRIDE) == (6, 24, 4)


@pytest.mark.parametrize(
    ("text", "expected"), [case[1:] for case in TOKENIZE_CASES], ids=[case[0] for case in TOKENIZE_CASES]
)
def test_tokenize_matches_js(text: str, expected: list[str]) -> None:
    assert tokenize(text) == expected


@pytest.mark.parametrize(
    ("text", "stride", "words", "chars", "word_count"),
    [case[1:] for case in SHINGLE_CASES],
    ids=[case[0] for case in SHINGLE_CASES],
)
def test_build_shingles_matches_js(
    text: str, stride: float | None, words: list[int], chars: list[int], word_count: int
) -> None:
    result = build(text, stride)
    assert sorted(result.words) == words
    assert sorted(result.chars) == chars
    assert result.word_count == word_count


def test_build_shingles_hashes_with_fnv1a32_over_the_joined_window() -> None:
    result = build_shingles("a b c d e f g h")
    assert result.words == {fnv1a32("a b c d e f"), fnv1a32("b c d e f g"), fnv1a32("c d e f g h")}
    assert result.chars == {fnv1a32("a b c d e f g h")}


def test_build_shingles_defaults_to_the_documented_char_stride() -> None:
    text = "x" * CHAR_SHINGLE + "abcdefgh"
    assert build_shingles(text) == build_shingles(text, CHAR_STRIDE)
    assert len(build_shingles(text).chars) == 3
    assert len(build_shingles(text, 1).chars) == 9


def test_build_shingles_returns_a_shingle_set_dataclass() -> None:
    assert dataclasses.is_dataclass(ShingleSet)
    assert [f.name for f in dataclasses.fields(ShingleSet)] == ["words", "chars", "word_count"]
    assert isinstance(build_shingles("a b"), ShingleSet)


@pytest.mark.parametrize(
    ("needle", "hay", "word", "char", "matched"),
    [case[1:] for case in CONTAINMENT_CASES],
    ids=[case[0] for case in CONTAINMENT_CASES],
)
def test_containment_matches_js(needle: Any, hay: Any, word: float, char: float, matched: int) -> None:
    result = containment(resolve(needle), resolve(hay))
    assert isinstance(result, Containment)
    assert (result.word, result.char, result.matched) == (word, char, matched)


def test_containment_of_a_verbatim_substring_counts_every_needle_shingle() -> None:
    needle = build_shingles(NEEDLE)
    result = containment(NEEDLE, HAY)
    assert result.matched == len(needle.words) + len(needle.chars)


def test_containment_returns_a_containment_dataclass() -> None:
    assert dataclasses.is_dataclass(Containment)
    assert [f.name for f in dataclasses.fields(Containment)] == ["word", "char", "matched"]
