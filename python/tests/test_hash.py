"""RED tests for prompt_protection.hash.fnv1a32 (expected values come from Node 22)."""

import pytest

from prompt_protection.hash import fnv1a32

# Expected values: fnv1a32 body extracted from dist/index.js (src/utils/hash.ts), run under node 22.
FNV_OFFSET = 2166136261


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", 2166136261),
        ("a", 3826002220),
        ("abc", 440920331),
        ("hello world", 3582672807),
        ("foo bar", 1170285226),
        ("é", 1812687940),
        ("€", 2839424075),
        ("日本語", 1409693518),
        ("\u0000", 84696351),
        ("😀", 3409036472),
        ("a😀b", 2412414209),
        ("😀x", 2673392192),
        ("\ud83d", 931276136),
        ("\ude00", 75411231),
        ("a" * 1000, 500786573),
        ("😀" * 50, 1170931021),
    ],
    ids=[
        "empty",
        "a",
        "abc",
        "hello-world",
        "two-words",
        "bmp-accent",
        "euro",
        "cjk",
        "nul",
        "emoji",
        "emoji-embedded",
        "emoji-prefix",
        "lone-high-surrogate",
        "lone-low-surrogate",
        "long-ascii",
        "long-astral",
    ],
)
def test_fnv1a32_matches_js_over_utf16_code_units(text: str, expected: int) -> None:
    result = fnv1a32(text)
    assert isinstance(result, int)
    assert result == expected


def test_fnv1a32_empty_input_returns_the_offset_basis() -> None:
    assert fnv1a32("") == FNV_OFFSET


def test_fnv1a32_ascii_matches_the_published_bytewise_vector() -> None:
    # Public FNV-1a 32-bit test vector for "a" is 0xe40c292c.
    assert fnv1a32("a") == 0xE40C292C


# node: fnv1a32('abc', seed) for each seed below, same extracted function.
@pytest.mark.parametrize(
    ("seed", "expected"),
    [
        (0, 2796870176),
        (12345, 1289640455),
        (2**32 + 5, 4231375947),
        (5, 4231375947),
        (-1, 3271184753),
        (0xFFFFFFFF, 3271184753),
    ],
    ids=["zero-seed", "12345", "wraps-above-2**32", "5", "negative-wraps", "all-ones"],
)
def test_fnv1a32_seed_is_taken_modulo_2_32(seed: int, expected: int) -> None:
    assert fnv1a32("abc", seed) == expected


def test_fnv1a32_empty_input_returns_the_seed() -> None:
    assert fnv1a32("", 7) == 7
