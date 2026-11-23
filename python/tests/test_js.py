"""RED tests for prompt_protection._js (plan design item 3, D32: expected values come from Node 22)."""

import re

import pytest
from prompt_protection._js import (
    JS_DOT,
    JS_WHITESPACE,
    code_units,
    cp_to_utf16_offset,
    decode_uri_component,
    js_number_str,
    js_round,
    utf16_len,
    utf16_slice,
    utf16_to_cp_offset,
)

FLAG_SETS = pytest.param(0, id="no-flags"), pytest.param(re.ASCII | re.IGNORECASE, id="ascii-ignorecase")

# node -e 'for(let c=0;c<0x110000;c++)if(/\s/u.test(String.fromCodePoint(c)))console.log(c.toString(16))'
JS_WHITESPACE_CODE_POINTS = {
    0x9, 0xA, 0xB, 0xC, 0xD, 0x20, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
    0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
}  # fmt: skip
# node -e 'for(let c=0;c<0x110000;c++)if(!/./u.test(String.fromCodePoint(c)))console.log(c.toString(16))'
JS_NON_DOT_CODE_POINTS = {0xA, 0xD, 0x2028, 0x2029}


def matching_code_points(source: str, flags: int) -> set[int]:
    pattern = re.compile(source, flags)
    return {cp for cp in range(0x110000) if pattern.fullmatch(chr(cp))}


# node -e 'for (const s of [...]) console.log(JSON.stringify(s), s.length)'
@pytest.mark.parametrize(
    ("text", "expected"),
    [("", 0), ("abc", 3), ("é", 1), ("日本語", 3), ("😀", 2), ("a😀b", 4), ("😀😀", 4), ("\ud83d", 1)],
    ids=["empty", "ascii", "bmp-accent", "cjk", "emoji", "emoji-embedded", "two-emoji", "lone-high-surrogate"],
)
def test_utf16_len_counts_code_units(text: str, expected: int) -> None:
    assert utf16_len(text) == expected


# node -e 'const s="a😀b"; for (const c of [...]) console.log(JSON.stringify(s.slice(a,b)))'
@pytest.mark.parametrize(
    ("text", "start", "end", "expected"),
    [
        ("a😀b", 0, 2, "a\ud83d"),
        ("a😀b", 1, 3, "😀"),
        ("a😀b", 2, 4, "\ude00b"),
        ("a😀b", 0, 4, "a😀b"),
        ("a😀b", 1, 2, "\ud83d"),
        ("a😀b", 2, 3, "\ude00"),
        ("a😀b", 3, 4, "b"),
        ("a😀b", 2, None, "\ude00b"),
        ("a😀b", 0, 99, "a😀b"),
        ("a😀b", 3, 1, ""),
        ("a😀b", 2, 2, ""),
        ("😀😀", 1, 3, "\ude00\ud83d"),
        ("x\ud83dy", 1, 2, "\ud83d"),
        ("abc", 1, None, "bc"),
        ("abc", 5, 9, ""),
    ],
    ids=[
        "cut-after-high",
        "whole-pair",
        "from-low",
        "all",
        "high-only",
        "low-only",
        "tail-ascii",
        "open-end-from-low",
        "end-clamped",
        "start-after-end",
        "empty-range",
        "straddles-two-pairs",
        "lone-surrogate-kept",
        "ascii-open-end",
        "start-past-length",
    ],
)
def test_utf16_slice_matches_js_slice(text: str, start: int, end: int | None, expected: str) -> None:
    assert utf16_slice(text, start, end) == expected


# node -e 'const cps=Array.from(s); for(k=0;k<=cps.length;k++) console.log(cps.slice(0,k).join("").length)'
OFFSET_TABLE = [
    ("a😀b", [0, 1, 3, 4]),
    ("😀😀", [0, 2, 4]),
    ("日本語", [0, 1, 2, 3]),
    ("", [0]),
    ("x\ud83dy", [0, 1, 2, 3]),
]


@pytest.mark.parametrize(("text", "units"), OFFSET_TABLE, ids=["emoji-embedded", "two-emoji", "cjk", "empty", "lone"])
def test_offsets_convert_between_code_points_and_utf16_units(text: str, units: list[int]) -> None:
    assert [cp_to_utf16_offset(text, k) for k in range(len(units))] == units
    assert [utf16_to_cp_offset(text, u) for u in units] == list(range(len(units)))


# node -e 'const s=...; console.log(Array.from({length:s.length},(_, i)=>s.charCodeAt(i)))'
@pytest.mark.parametrize(
    ("text", "expected"),
    [("", []), ("a😀b", [97, 0xD83D, 0xDE00, 98]), ("\ud83d", [0xD83D]), ("\ude00\ud83d", [0xDE00, 0xD83D])],
    ids=["empty", "emoji-embedded", "lone-high", "reversed-pair"],
)
def test_code_units_lists_utf16_units(text: str, expected: list[int]) -> None:
    assert code_units(text) == expected


# node -e 'for (const x of [...]) console.log(x, Math.round(x))'
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (2.5, 3),
        (-2.5, -2),
        (0.5, 1),
        (-0.5, 0),
        (1.5, 2),
        (-1.5, -1),
        (2.4, 2),
        (-2.6, -3),
        (0, 0),
        (0.49999999999999994, 0),
        (-0.49999999999999994, 0),
        (0.5000000000000001, 1),
        (1000000000000000.5, 1000000000000001),
        (18.12692469220182, 18),
    ],
    ids=[
        "2.5",
        "-2.5",
        "0.5",
        "-0.5",
        "1.5",
        "-1.5",
        "2.4",
        "-2.6",
        "zero",
        "just-below-half",
        "negative-just-below-half",
        "just-above-half",
        "large-half",
        "score-formula",
    ],
)
def test_js_round_is_half_toward_positive_infinity(value: float, expected: int) -> None:
    assert js_round(value) == expected


# node -e 'for (const x of [...]) console.log(String(x))'
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (0.1, "0.1"),
        (123e-20, "1.23e-18"),
        (-0.0, "0"),
        (0.0, "0"),
        (2**53, "9007199254740992"),
        (float(2**53), "9007199254740992"),
        (5e-324, "5e-324"),
        (1.0, "1"),
        (-1.0, "-1"),
        (5, "5"),
        (100.0, "100"),
        (1.5, "1.5"),
        (1e20, "100000000000000000000"),
        (123456789012345680000.0, "123456789012345680000"),
        (1e-6, "0.000001"),
        (-1e-7, "-1e-7"),
        (-1.5e-10, "-1.5e-10"),
        (0.30000000000000004, "0.30000000000000004"),
        (12345.6789, "12345.6789"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (1e100, "1e+100"),
    ],
    ids=[
        "1e21",
        "1e-7",
        "0.1",
        "123e-20",
        "negative-zero",
        "zero",
        "2**53-int",
        "2**53-float",
        "5e-324",
        "whole-float",
        "negative-whole-float",
        "int",
        "hundred",
        "1.5",
        "1e20-stays-positional",
        "21-digit-integer",
        "1e-6-stays-positional",
        "negative-1e-7",
        "negative-small",
        "float-noise",
        "decimal",
        "max-double",
        "1e100",
    ],
)
def test_js_number_str_matches_number_to_string(value: float, expected: str) -> None:
    assert js_number_str(value) == expected


# node -e 'for (const s of [...]) { try { r = decodeURIComponent(s) } catch { r = s } console.log(JSON.stringify(r)) }'
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("%E2%82%AC", "€"),
        ("%41", "A"),
        ("%C3%A9", "é"),
        ("%F0%9F%98%80", "😀"),
        ("a%20b", "a b"),
        ("abc", "abc"),
        ("", ""),
        ("%E0%A4", "%E0%A4"),
        ("%", "%"),
        ("%zz", "%zz"),
        ("%C0%AF", "%C0%AF"),
        ("%ED%A0%80", "%ED%A0%80"),
        ("%80", "%80"),
        ("%F0%9F%98", "%F0%9F%98"),
        ("%E2%82%AC%E0%A4", "%E2%82%AC%E0%A4"),
    ],
    ids=[
        "euro",
        "ascii-escape",
        "two-byte",
        "four-byte-emoji",
        "space",
        "plain",
        "empty",
        "truncated-three-byte",
        "bare-percent",
        "non-hex",
        "overlong",
        "encoded-surrogate",
        "stray-continuation",
        "truncated-four-byte",
        "valid-then-malformed-keeps-whole-input",
    ],
)
def test_decode_uri_component_keeps_input_on_bad_utf8(text: str, expected: str) -> None:
    assert decode_uri_component(text) == expected


@pytest.mark.parametrize("flags", FLAG_SETS)
def test_js_whitespace_matches_exactly_the_25_js_whitespace_code_points(flags: int) -> None:
    assert len(JS_WHITESPACE_CODE_POINTS) == 25
    assert matching_code_points(JS_WHITESPACE, flags) == JS_WHITESPACE_CODE_POINTS


@pytest.mark.parametrize("flags", FLAG_SETS)
def test_js_dot_excludes_exactly_lf_cr_and_the_two_line_separators(flags: int) -> None:
    expected = set(range(0x110000)) - JS_NON_DOT_CODE_POINTS
    assert matching_code_points(JS_DOT, flags) == expected


@pytest.mark.parametrize("source", [JS_WHITESPACE, JS_DOT], ids=["JS_WHITESPACE", "JS_DOT"])
def test_class_constants_are_written_with_escapes(source: str) -> None:
    assert source.isascii()
