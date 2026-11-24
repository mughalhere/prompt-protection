"""Gap tests for PY-12: a session's default ml at create_guard, and the stringify_value branches.

The JS outputs below were measured with Node on src/guard/provenance.ts#stringifyValue.
A Python int past float range is treated as a JS bigint. A case with no JS analog pins the Python output.
"""

from typing import Any

import pytest

from prompt_protection import DeferredFeatureError, create_protection_session
from prompt_protection.guard import ToolCall, create_guard, stringify_value

ML_MESSAGE = r"(?i)\bml\b"
BIG = 10**400
BIG_DIGITS = "1" + "0" * 400
FLOAT_MAX = 1.7976931348623157e308


class Fields:
    def __init__(self) -> None:
        self.x = 1
        self.y = "a"


class NoFields:
    pass


class RaisingStr(dict[str, Any]):
    def __str__(self) -> str:
        raise RuntimeError("no text")


def deep_list(depth: int) -> list[Any]:
    root: list[Any] = []
    tail = root
    for _ in range(depth):
        inner: list[Any] = []
        tail.append(inner)
        tail = inner
    return root


@pytest.mark.parametrize("fail_mode", ["closed", "open"])
@pytest.mark.parametrize("ml", ["escalate", "hybrid", "bogus"])
def test_a_session_default_ml_other_than_off_raises_at_create_guard(ml: str, fail_mode: str) -> None:
    defaults: dict[str, Any] = {"ml": ml}
    with pytest.raises(DeferredFeatureError, match=ML_MESSAGE):
        create_guard(session=create_protection_session(**defaults), fail_mode=fail_mode)  # type: ignore[arg-type]


@pytest.mark.parametrize("fail_mode", ["closed", "open"])
@pytest.mark.parametrize("defaults", [{"ml": "off"}, {"ml": None}, {}], ids=["ml-off", "ml-none", "no-ml"])
def test_a_session_with_ml_off_or_no_ml_builds_a_working_guard(defaults: dict[str, Any], fail_mode: str) -> None:
    session = create_protection_session(**defaults)
    guard = create_guard(session=session, fail_mode=fail_mode)  # type: ignore[arg-type]
    assert guard.session is session
    assert guard.taint("t", "hello").injection.action == "allow"
    assert guard.check_tool_call(ToolCall(tool_name="search", args={"q": "x"})).action == "allow"


def case(value: Any, expected: str, case_id: str) -> Any:
    return pytest.param(value, expected, id=case_id)


NODE_CASES = [
    case(BIG, BIG_DIGITS, "int-past-float-range-is-a-bigint"),
    case(-BIG, "-" + BIG_DIGITS, "negative-int-past-float-range"),
    case(2**1024, str(2**1024), "first-int-past-float-range"),
    case(int(FLOAT_MAX), "1.7976931348623157e+308", "largest-float-int-is-a-number"),
    case({"a": int(FLOAT_MAX)}, '{"a":1.7976931348623157e+308}', "nested-largest-float-int"),
    case({"a": BIG}, "[object Object]", "nested-bigint-in-a-dict"),
    case({"a": 1, "b": BIG}, "[object Object]", "nested-bigint-after-a-key"),
    case([{"a": BIG}], "[object Object]", "nested-bigint-in-a-dict-in-a-list"),
    case([1, BIG], "1," + BIG_DIGITS, "nested-bigint-in-a-list"),
    case((1, BIG), "1," + BIG_DIGITS, "nested-bigint-in-a-tuple"),
    case({1, 2}, "{}", "set"),
    case(set(), "{}", "empty-set"),
    case(frozenset({1}), "{}", "frozenset"),
    case({"a": {1}}, '{"a":{}}', "set-in-a-dict"),
    case([{1}], "[{}]", "set-in-a-list"),
    case(Fields(), '{"x":1,"y":"a"}', "instance-is-its-own-fields"),
    case(NoFields(), "{}", "instance-without-fields"),
    case({"a": Fields()}, '{"a":{"x":1,"y":"a"}}', "instance-in-a-dict"),
    case([Fields(), 1], '[{"x":1,"y":"a"},1]', "instance-in-a-list"),
    case({1: "a", 2: "b"}, '{"1":"a","2":"b"}', "int-keys"),
    case({-1: 1}, '{"-1":1}', "negative-int-key"),
    case({"b": 1, 2: "x"}, '{"2":"x","b":1}', "int-key-sorts-as-an-array-index"),
    case({1: "a", "1": "b"}, '{"1":"b"}', "int-key-and-str-key-collide"),
    case({1.5: 1}, '{"1.5":1}', "float-key"),
    case({1e21: 1}, '{"1e+21":1}', "large-float-key"),
    case({1.0: 1}, '{"1":1}', "integral-float-key-is-a-js-number-key"),
    case({True: 1}, '{"true":1}', "bool-key-is-a-js-boolean-key"),
    case({None: 1}, '{"null":1}', "none-key-is-the-js-null-key"),
]


@pytest.mark.parametrize(("value", "expected"), NODE_CASES)
def test_stringify_value_matches_node_on_the_closest_js_analog(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [case(b"abc", "b'abc'", "bytes"), case({"a": b"abc"}, "{'a': b'abc'}", "bytes-in-a-dict")],
)
def test_stringify_value_with_no_js_analog_falls_back_to_the_python_str(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


def test_stringify_value_falls_back_to_the_object_repr_when_str_raises() -> None:
    value = RaisingStr()
    value["self"] = value
    assert stringify_value(value) == object.__repr__(value)


def test_stringify_value_returns_text_for_a_list_nested_past_the_recursion_limit() -> None:
    assert isinstance(stringify_value(deep_list(100_000)), str)


def test_taint_accepts_a_list_nested_past_the_recursion_limit() -> None:
    assert isinstance(create_guard().taint("t", deep_list(100_000)).text, str)
