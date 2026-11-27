"""stringify_value on an int past the int-to-str digit limit.

At most 4300 decimal digits prints exact decimal. More prints hex() for that int only.
The limit is min(4300, sys.get_int_max_str_digits()) when that exists, 4300 when it is 0 or absent,
and never depends on the version. A value outside the narrowed contract prints a marker, so no int in it prints.
"""

import sys
from collections import OrderedDict, defaultdict, deque, namedtuple
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from prompt_protection.guard import stringify_value

OVER = 10**4300
AT = 10**4299
AT_TEXT = "1" + "0" * 4299
SIBLING = "visible-sibling"


def marker(qualname: str) -> str:
    return f"<{qualname} not rendered>"


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
def test_an_ordereddict_deque_or_namedtuple_with_an_over_limit_int_prints_only_its_marker(value: Any) -> None:
    text = stringify_value(value)
    assert text == marker(type(value).__qualname__)
    assert SIBLING not in text
    assert hex(OVER) not in text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(deque([OVER, SIBLING]), "<deque not rendered>", id="deque"),
        pytest.param(Pair(OVER, SIBLING), "<Pair not rendered>", id="namedtuple"),
    ],
)
def test_a_deque_or_namedtuple_prints_a_marker_and_none_of_its_items(value: Any, expected: str) -> None:
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


class Plain:
    def __init__(self, x: int, s: str) -> None:
        self.x = x
        self.s = s


class Slotted:
    __slots__ = ("x", "s")

    def __init__(self, x: int, s: str) -> None:
        self.x = x
        self.s = s


CUSTOM_TEXT = "custom-str-text"


class CustomStr:
    def __init__(self, x: int) -> None:
        self.x = x

    def __str__(self) -> str:
        return CUSTOM_TEXT


class Node:
    def __init__(self, sibling: str) -> None:
        self.sibling = sibling
        self.other: Node | None = None


def _stringify_or_fail(value: Any) -> str:
    try:
        return stringify_value(value)
    except RecursionError:
        pytest.fail("stringify_value raised RecursionError on a cycle")


@pytest.mark.parametrize("number", [5, OVER], ids=["small-int-field", "over-limit-int-field"])
@pytest.mark.parametrize("cls", [Plain, Slotted], ids=["dict-instance", "slots-instance"])
def test_an_object_without_its_own_str_prints_a_marker_and_none_of_its_fields(cls: type, number: int) -> None:
    text = stringify_value(cls(number, SIBLING))
    assert text == marker(cls.__qualname__)
    assert SIBLING not in text
    assert (hex(number) if number == OVER else str(number)) not in text


@pytest.mark.parametrize("number", [5, OVER], ids=["small-int-field", "over-limit-int-field"])
def test_an_object_with_its_own_str_prints_a_marker_and_neither_its_fields_nor_that_str(number: int) -> None:
    shown = hex(number) if number == OVER else str(number)
    text = stringify_value(CustomStr(number))
    assert text == marker("CustomStr")
    assert shown not in text
    assert CUSTOM_TEXT not in text


def _self_cycle() -> Node:
    node = Node(SIBLING)
    node.other = node
    return node


def _two_object_cycle() -> Node:
    first, second = Node(SIBLING), Node("visible-second")
    first.other, second.other = second, first
    return first


@pytest.mark.parametrize(
    ("build", "visible"),
    [
        pytest.param(_self_cycle, [SIBLING], id="self-cycle"),
        pytest.param(_two_object_cycle, [SIBLING, "visible-second"], id="two-object-cycle"),
    ],
)
def test_a_cycle_of_plain_objects_terminates_and_prints_a_marker_that_hides_every_sibling(
    build: Callable[[], Node], visible: list[str]
) -> None:
    text = _stringify_or_fail(build())
    assert text == marker("Node")
    for sibling in visible:
        assert sibling not in text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(defaultdict(list, {"a": OVER, "b": SIBLING}), marker("defaultdict"), id="defaultdict"),
        pytest.param(
            defaultdict(None, {"a": OVER, "b": SIBLING}), marker("defaultdict"), id="defaultdict-without-factory"
        ),
        pytest.param(
            [defaultdict(list, {"a": OVER}), SIBLING],
            f"[{marker('defaultdict')}, '{SIBLING}']",
            id="defaultdict-in-a-list",
        ),
        pytest.param(
            {"d": defaultdict(int, {"a": OVER}), "b": SIBLING},
            f"{{'d': {marker('defaultdict')}, 'b': '{SIBLING}'}}",
            id="defaultdict-in-a-dict",
        ),
    ],
)
def test_a_defaultdict_with_an_over_limit_int_prints_a_marker_and_keeps_the_siblings_of_exact_containers(
    value: Any, expected: str
) -> None:
    text = stringify_value(value)
    assert text == expected
    assert hex(OVER) not in text


RANGE_CASES = [
    pytest.param(range(OVER), f"range(0, {hex(OVER)})", id="stop-over-limit"),
    pytest.param(range(0, OVER, 1), f"range(0, {hex(OVER)})", id="explicit-step-1-is-not-printed"),
    pytest.param(range(7, OVER, 3), f"range(7, {hex(OVER)}, 3)", id="stop-over-limit-with-step"),
    pytest.param(range(-OVER, 0), f"range({hex(-OVER)}, 0)", id="negative-start-over-limit"),
    pytest.param(range(0, 10, OVER), f"range(0, 10, {hex(OVER)})", id="step-over-limit"),
    pytest.param(range(AT), f"range(0, {AT_TEXT})", id="stop-at-limit-stays-decimal"),
    pytest.param(range(5), "range(0, 5)", id="in-range-stop-only"),
    pytest.param(range(0, 10, 2), "range(0, 10, 2)", id="in-range-with-step"),
    pytest.param(range(5, 0, -1), "range(5, 0, -1)", id="in-range-negative-step"),
    pytest.param([range(0, OVER), SIBLING], f"[range(0, {hex(OVER)}), '{SIBLING}']", id="over-limit-range-in-a-list"),
    pytest.param(
        {"r": range(OVER), "b": SIBLING}, f"{{'r': range(0, {hex(OVER)}), 'b': '{SIBLING}'}}", id="range-in-a-dict"
    ),
]


@pytest.mark.parametrize(("value", "expected"), RANGE_CASES)
def test_a_range_prints_python_str_with_only_an_over_limit_bound_as_hex(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


def json_shaped(depth: int) -> dict[str, Any]:
    """Build nested dicts and lists the way json.loads does, with SIBLING one level below the root."""
    node: Any = "leaf"
    for level in range(depth):
        node = {"k": node} if level % 2 == 0 else [node]
    return {"sibling": SIBLING, "k": node}


@pytest.mark.parametrize("depth", [500, 1000, 5000])
def test_json_shaped_nesting_past_the_renderer_depth_keeps_the_depth_1_sibling_visible(depth: int) -> None:
    value = json_shaped(depth)
    try:
        text = stringify_value(value)
    except RecursionError:
        pytest.fail("stringify_value raised RecursionError on deeply nested JSON-shaped data")
    assert SIBLING in text
    assert " object at 0x" not in text
