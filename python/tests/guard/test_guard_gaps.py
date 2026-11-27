"""Gap tests for the core guard: a session's default ml at create_guard, and the stringify_value branches.

The JS outputs named below were measured with Node on src/guard/provenance.ts#stringifyValue.
A Python int past float range is treated as a JS bigint at top level.
A test named owner_divergence pins Python's own text where Python deliberately differs from JS.
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
    case({1: "a", 2: "b"}, '{"1":"a","2":"b"}', "int-keys"),
    case({-1: 1}, '{"-1":1}', "negative-int-key"),
    case({"b": 1, 2: "x"}, '{"2":"x","b":1}', "int-key-sorts-as-an-array-index"),
    case({1.5: 1}, '{"1.5":1}', "float-key"),
    case({1e21: 1}, '{"1e+21":1}', "large-float-key"),
]


@pytest.mark.parametrize(("value", "expected"), NODE_CASES)
def test_stringify_value_matches_node_on_the_closest_js_analog(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


def divergence(value: Any, case_id: str, expected: str | None = None) -> Any:
    return pytest.param(value, str(value) if expected is None else expected, id="owner-divergence-" + case_id)


# A documented divergence from JS: Python keeps str() for these. JS prints [object Object], {} or the object's fields.
NESTED_BIGINT_CASES = [
    divergence({"a": BIG}, "dict", "{'a': " + BIG_DIGITS + "}"),
    divergence({"a": 1, "b": BIG}, "dict-after-a-key", "{'a': 1, 'b': " + BIG_DIGITS + "}"),
    divergence([{"a": BIG}], "dict-in-a-list", "[{'a': " + BIG_DIGITS + "}]"),
    divergence([1, BIG], "list", "[1, " + BIG_DIGITS + "]"),
    divergence((1, BIG), "tuple", "(1, " + BIG_DIGITS + ")"),
]
SET_CASES = [
    divergence({1, 2}, "set", "{1, 2}"),
    divergence(set(), "empty-set", "set()"),
    divergence(frozenset({1}), "frozenset", "frozenset({1})"),
    divergence({"a": {1}}, "set-in-a-dict", "{'a': {1}}"),
    divergence([{1}], "set-in-a-list", "[{1}]"),
]
# A documented divergence from JS: a plain instance prints a <Name not rendered> marker, not its fields.
INSTANCE_CASES = [
    divergence(Fields(), "instance", "<Fields not rendered>"),
    divergence(NoFields(), "instance-without-fields", "<NoFields not rendered>"),
    divergence({"a": Fields()}, "instance-in-a-dict", "{'a': <Fields not rendered>}"),
    divergence([Fields(), 1], "instance-in-a-list", "[<Fields not rendered>, 1]"),
]
# A documented divergence from JS: JSON would keep one pair, so the Python text shows both.
COLLISION_CASES = [divergence({1: "a", "1": "b"}, "int-key-and-str-key-collide", "{1: 'a', '1': 'b'}")]
KEY_CASES = [
    divergence({1.0: 1}, "integral-float-key", '{"1.0":1}'),
    divergence({True: 1}, "bool-key", '{"True":1}'),
    divergence({None: 1}, "none-key", '{"None":1}'),
]


@pytest.mark.parametrize(("value", "expected"), NESTED_BIGINT_CASES)
def test_stringify_value_keeps_python_str_for_a_nested_int_past_float_range_owner_divergence(
    value: Any, expected: str
) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize(("value", "expected"), SET_CASES)
def test_stringify_value_keeps_python_str_for_a_set_owner_divergence(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize(("value", "expected"), INSTANCE_CASES)
def test_stringify_value_prints_a_plain_instance_as_a_marker_owner_decision(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize(("value", "expected"), COLLISION_CASES)
def test_stringify_value_prints_both_pairs_of_an_int_and_str_key_collision_owner_divergence(
    value: Any, expected: str
) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize(("value", "expected"), KEY_CASES)
def test_stringify_value_keeps_python_str_for_a_bool_none_or_integral_float_key_owner_divergence(
    value: Any, expected: str
) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [case(b"abc", "b'abc'", "bytes"), case({"a": b"abc"}, "{'a': b'abc'}", "bytes-in-a-dict")],
)
def test_stringify_value_with_no_js_analog_falls_back_to_the_python_str(value: Any, expected: str) -> None:
    assert stringify_value(value) == expected


def test_stringify_value_prints_a_marker_for_a_dict_subclass_without_raising_when_its_str_raises() -> None:
    value = RaisingStr()
    value["self"] = value
    text = stringify_value(value)
    assert text == "<RaisingStr not rendered>"


def test_stringify_value_returns_text_for_a_list_nested_past_the_recursion_limit() -> None:
    assert isinstance(stringify_value(deep_list(100_000)), str)


def test_taint_accepts_a_list_nested_past_the_recursion_limit() -> None:
    assert isinstance(create_guard().taint("t", deep_list(100_000)).text, str)


@pytest.mark.parametrize("fail_mode", ["closed", "open"])
@pytest.mark.parametrize("session_ml", ["escalate", "hybrid"])
def test_an_analyze_options_ml_off_overrides_a_session_default_ml_at_create_guard(
    session_ml: str, fail_mode: str
) -> None:
    defaults: dict[str, Any] = {"ml": session_ml}
    session = create_protection_session(**defaults)
    guard = create_guard(session=session, analyze_options={"ml": "off"}, fail_mode=fail_mode)  # type: ignore[arg-type]
    assert guard.session is session
    assert guard.taint("t", "hello").injection.action == "allow"
    assert guard.check_tool_call(ToolCall(tool_name="search", args={"q": "x"})).action == "allow"


@pytest.mark.parametrize("fail_mode", ["closed", "open"])
@pytest.mark.parametrize("call_ml", ["escalate", "hybrid"])
def test_an_analyze_options_ml_other_than_off_raises_even_when_the_session_default_ml_is_off(
    call_ml: str, fail_mode: str
) -> None:
    session = create_protection_session(ml="off")
    with pytest.raises(DeferredFeatureError, match=ML_MESSAGE):
        create_guard(session=session, analyze_options={"ml": call_ml}, fail_mode=fail_mode)  # type: ignore[arg-type]


@pytest.mark.parametrize("fail_mode", ["closed", "open"])
def test_an_analyze_options_ml_none_overrides_a_session_default_ml_at_create_guard(fail_mode: str) -> None:
    """A present ml key set to None is the override: JS ``{...a, ...{ml: undefined}}`` leaves ml undefined (off)."""
    defaults: dict[str, Any] = {"ml": "escalate"}
    session = create_protection_session(**defaults)
    guard = create_guard(session=session, analyze_options={"ml": None}, fail_mode=fail_mode)  # type: ignore[arg-type]
    assert guard.session is session
    assert guard.taint("t", "hello").injection.action == "allow"
    assert guard.check_tool_call(ToolCall(tool_name="search", args={"q": "x"})).action == "allow"
