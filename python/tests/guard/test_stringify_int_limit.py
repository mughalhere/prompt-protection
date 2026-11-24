"""stringify_value on an int past the int-to-str digit limit (bead j8o, owner decision 2026-11-24).

At most 4300 decimal digits prints exact decimal. More prints hex() for that int only.
The limit is sys.get_int_max_str_digits() when it exists, else 4300, and never depends on the version.
"""

import sys
from collections import OrderedDict, deque, namedtuple
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from prompt_protection.guard import stringify_value

OVER = 10**4300
AT = 10**4299
AT_TEXT = "1" + "0" * 4299
SIBLING = "visible-sibling"


@pytest.fixture(autouse=True, params=["interpreter-limit", "attribute-absent"])
def digit_limit_source(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    if request.param == "attribute-absent":
        monkeypatch.delattr(sys, "get_int_max_str_digits", raising=False)
    yield


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(OVER, hex(OVER), id="4301-digits-alone"),
        pytest.param(-OVER, hex(-OVER), id="negative-4301-digits-alone"),
        pytest.param(AT, AT_TEXT, id="4300-digits-alone"),
        pytest.param(-AT, "-" + AT_TEXT, id="negative-4300-digits-alone"),
    ],
)
def test_a_top_level_int_prints_exact_decimal_up_to_the_limit_and_hex_past_it(value: int, expected: str) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param([OVER, SIBLING], f"[{hex(OVER)}, '{SIBLING}']", id="list-over-limit"),
        pytest.param({"a": OVER, "b": SIBLING}, f"{{'a': {hex(OVER)}, 'b': '{SIBLING}'}}", id="dict-over-limit"),
        pytest.param([AT, SIBLING], f"[{AT_TEXT}, '{SIBLING}']", id="list-at-limit"),
        pytest.param({"a": AT, "b": SIBLING}, f"{{'a': {AT_TEXT}, 'b': '{SIBLING}'}}", id="dict-at-limit"),
    ],
)
def test_a_container_prints_python_str_with_only_the_over_limit_int_as_hex(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize("value", [[OVER, SIBLING], {"a": OVER, "b": SIBLING}], ids=["list", "dict"])
def test_a_container_with_an_over_limit_int_never_hides_its_siblings_behind_an_object_repr(value: Any) -> None:
    text = stringify_value(value)
    assert SIBLING in text
    assert hex(OVER) in text
    assert " object at 0x" not in text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param({OVER: "v"}, f'{{"{hex(OVER)}":"v"}}', id="key-over-limit-alone"),
        pytest.param({-OVER: "v"}, f'{{"{hex(-OVER)}":"v"}}', id="key-negative-over-limit-alone"),
        pytest.param({OVER: "v", "b": SIBLING}, f'{{"{hex(OVER)}":"v","b":"{SIBLING}"}}', id="key-over-limit-sibling"),
        pytest.param({AT: "v"}, f'{{"{AT_TEXT}":"v"}}', id="key-4300-digits-alone"),
        pytest.param({AT: "v", "b": SIBLING}, f'{{"{AT_TEXT}":"v","b":"{SIBLING}"}}', id="key-4300-digits-sibling"),
    ],
)
def test_a_mapping_key_prints_decimal_up_to_the_limit_and_hex_past_it(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


Pair = namedtuple("Pair", ["first", "second"])


def _other_containers() -> list[Any]:
    return [
        pytest.param(OrderedDict([("a", OVER), ("b", SIBLING)]), id="ordered-dict"),
        pytest.param(deque([OVER, SIBLING]), id="deque"),
        pytest.param(Pair(OVER, SIBLING), id="namedtuple"),
    ]


@pytest.mark.parametrize("value", _other_containers())
def test_an_ordereddict_deque_or_namedtuple_with_an_over_limit_int_shows_hex_and_keeps_its_siblings(value: Any) -> None:
    text = stringify_value(value)
    assert SIBLING in text
    assert hex(OVER) in text
    assert " object at 0x" not in text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(deque([OVER, SIBLING]), f"deque([{hex(OVER)}, '{SIBLING}'])", id="deque"),
        pytest.param(Pair(OVER, SIBLING), f"Pair(first={hex(OVER)}, second='{SIBLING}')", id="namedtuple"),
    ],
)
def test_a_deque_or_namedtuple_prints_python_str_with_only_the_over_limit_int_as_hex(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


@pytest.fixture
def set_limit(monkeypatch: pytest.MonkeyPatch) -> Callable[[int], None]:
    def apply(limit: int) -> None:
        monkeypatch.setattr(sys, "get_int_max_str_digits", lambda: limit, raising=False)

    return apply


LOW = 10**1000
LOW_TEXT = "1" + "0" * 1000
JUST_UNDER_LOW = 10**999
JUST_UNDER_LOW_TEXT = "1" + "0" * 999

LIMIT_CASES = [
    pytest.param(0, OVER, hex(OVER), id="unlimited-4301-digits"),
    pytest.param(0, AT, AT_TEXT, id="unlimited-4300-digits"),
    pytest.param(1000, LOW, hex(LOW), id="limit-1000-1001-digits"),
    pytest.param(1000, JUST_UNDER_LOW, JUST_UNDER_LOW_TEXT, id="limit-1000-1000-digits"),
    pytest.param(5000, OVER, hex(OVER), id="limit-5000-4301-digits"),
    pytest.param(5000, AT, AT_TEXT, id="limit-5000-4300-digits"),
]


@pytest.mark.parametrize(("limit", "value", "expected"), LIMIT_CASES)
def test_the_threshold_is_the_smaller_of_4300_and_the_interpreter_limit_and_4300_when_it_is_zero(
    set_limit: Callable[[int], None], limit: int, value: int, expected: str
) -> None:
    set_limit(limit)
    assert stringify_value(value) == expected


@pytest.mark.parametrize(("limit", "value", "expected"), LIMIT_CASES)
def test_the_same_threshold_applies_to_an_int_inside_a_list(
    set_limit: Callable[[int], None], limit: int, value: int, expected: str
) -> None:
    set_limit(limit)
    assert stringify_value([value, SIBLING]) == f"[{expected}, '{SIBLING}']"
