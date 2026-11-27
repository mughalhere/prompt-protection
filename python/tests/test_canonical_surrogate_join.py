"""Surrogate halves held apart join before escaping and sorting (follow-up).

Oracle: Node 22, dist/guard/index.js canonicalJson, digest and digestSyncWeak over strings and
keys built one UTF-16 unit at a time with String.fromCharCode(0xd83d) and (0xde00).
"""

import pytest

from prompt_protection.canonical import canonical_json, digest, digest_sync_weak

HI = "\ud83d"
LO = "\ude00"
EMOJI = "\U0001f600"

SPLIT_CASES = [
    pytest.param(
        HI + LO,
        '"\U0001f600"',
        "f0443a342c5ef54783a111b51ba56c938e474c32324d90c3a60c9c8e3a37e2d9",
        "feff073875020288",
        id="value-split-pair",
    ),
    pytest.param(
        "a" + HI + LO + "b",
        '"a\U0001f600b"',
        "6fba5b2ea783ded096fc2444d540ffbdf49168df30993b155b7efb683313f110",
        "33c526094d790e49",
        id="value-pair-in-text",
    ),
    pytest.param(
        HI + LO + HI + LO,
        '"\U0001f600\U0001f600"',
        "91ad485bf369a67f134962f4726eac8fc299a51f1504fc6835210fb32c4890f1",
        "4f702be469bdbe35",
        id="two-split-pairs",
    ),
    pytest.param(
        {HI + LO: 1},
        '{"\U0001f600":1}',
        "763606c9e0046348cc185a6e829e12ae6c0f3565b940f8184901a4d83dda6c33",
        "f7dd3db49278f95b",
        id="key-split-pair",
    ),
    pytest.param(
        {HI + LO: HI + LO},
        '{"\U0001f600":"\U0001f600"}',
        "e45e8aab3463250bfc2c1a098a3afb26c6bdc041831a1748a29bc07617cc404a",
        "7cbe276031ec0511",
        id="key-and-value-split-pair",
    ),
    pytest.param(
        {"\uff5e": 1, HI + LO: 2, "\u20ac": 3, "a": 4},
        '{"a":4,"\u20ac":3,"\U0001f600":2,"\uff5e":1}',
        "d4ced454372e9fc23b160cab19a13e6201164130ab4761fee5fb6f37f23672ee",
        "225d84e7ef870ff5",
        id="key-split-pair-sorts-by-utf16-unit",
    ),
    pytest.param(
        HI + HI + LO,
        '"\\ud83d\U0001f600"',
        "16bbb56893fdcd3874f3871c3ca69b3b380f4d94a9b7eeb600f66249de41b69f",
        "51a4f852817fdbb3",
        id="lone-high-then-split-pair",
    ),
    pytest.param(
        HI + LO + LO,
        '"\U0001f600\\ude00"',
        "43c07ec4819e4eb64f724ac552e7587fe21ce3110ed29797be89a927753b6578",
        "8ad7b3a7efb68129",
        id="split-pair-then-lone-low",
    ),
    pytest.param(
        LO + HI,
        '"\\ude00\\ud83d"',
        "52793f8dc1d85e409f8c88be99d8b31d58f676246340150f406289e04a11151e",
        "4aa8c8e4b7403347",
        id="reversed-halves-stay-lone",
    ),
]


def test_split_halves_are_two_code_points_in_python() -> None:
    assert len(HI + LO) == 2
    assert HI + LO != EMOJI


@pytest.mark.parametrize(("value", "expected", "_sha", "_weak"), SPLIT_CASES)
def test_canonical_json_joins_split_surrogate_halves(value: object, expected: str, _sha: str, _weak: str) -> None:
    assert canonical_json(value) == expected


def joined(value: object) -> object:
    if isinstance(value, dict):
        return {key.replace(HI + LO, EMOJI): item for key, item in value.items()}
    return value.replace(HI + LO, EMOJI) if isinstance(value, str) else value


@pytest.mark.parametrize(("value", "expected", "_sha", "_weak"), SPLIT_CASES)
def test_canonical_json_of_split_halves_equals_the_astral_form(
    value: object, expected: str, _sha: str, _weak: str
) -> None:
    assert canonical_json(joined(value)) == expected


@pytest.mark.parametrize(("value", "_expected", "sha", "_weak"), SPLIT_CASES)
def test_digest_of_split_halves_matches_node(value: object, _expected: str, sha: str, _weak: str) -> None:
    assert digest(value) == f"sha256:{sha}"


@pytest.mark.parametrize(("value", "_expected", "_sha", "weak"), SPLIT_CASES)
def test_digest_sync_weak_of_split_halves_matches_node(value: object, _expected: str, _sha: str, weak: str) -> None:
    assert digest_sync_weak(value) == f"fnv1a64:{weak}"
