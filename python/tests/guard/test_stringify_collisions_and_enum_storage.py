"""stringify_value: key-text collisions and Enum value storage (bead j8o, owner decision 2026-11-25, option A).

Two keys of one exact dict can print as the same key text. The JSON form would keep one pair, so the
value of the other pair would vanish. A dict like that has no JSON form: the Python text prints every pair.
An Enum member prints the value held in its own storage. No property getter, no ``__dict__`` property and
no ``__getattribute__`` override of its class runs. A member with no stored value prints the marker.
"""

import types
from collections.abc import Callable
from enum import Enum, EnumMeta, IntEnum
from typing import Any

import pytest

from prompt_protection.guard import create_guard, stringify_value

SIBLING = "visible-sibling"
CALLS: list[str] = []


@pytest.fixture(autouse=True)
def no_calls() -> None:
    CALLS.clear()


class Opaque:
    pass


class Label(Enum):
    GREEN = "visible-enum-text"


class Level(IntEnum):
    HIGH = 4242


def marker(value: Any) -> str:
    return f"<{type(value).__qualname__} not rendered>"


def flagged(value: Any) -> Any:
    return create_guard().taint("tool", value)


PLACES: dict[str, tuple[Callable[[Any], Any], Callable[[str], str]]] = {
    "alone": (lambda v: v, lambda text: text),
    "in-an-exact-list": (lambda v: [v, SIBLING], lambda text: f"[{text}, '{SIBLING}']"),
    "in-an-exact-dict": (lambda v: {"k": v, "s": SIBLING}, lambda text: f"{{'k': {text}, 's': '{SIBLING}'}}"),
}

KEY_OPAQUE = Opaque()
# id -> (the colliding dict, its Python text, whether a key printed the marker, the two values)
COLLISIONS: dict[str, tuple[dict[Any, str], str, bool, tuple[str, str]]] = {
    "int-vs-str": ({1: "EVIL-INT", "1": "ok-int"}, "{1: 'EVIL-INT', '1': 'ok-int'}", False, ("EVIL-INT", "ok-int")),
    "none-vs-str": (
        {None: "EVIL-NONE", "None": "ok-none"},
        "{None: 'EVIL-NONE', 'None': 'ok-none'}",
        False,
        ("EVIL-NONE", "ok-none"),
    ),
    "tuple-vs-str": (
        {(1,): "EVIL-TUP", "(1,)": "ok-tup"},
        "{(1,): 'EVIL-TUP', '(1,)': 'ok-tup'}",
        False,
        ("EVIL-TUP", "ok-tup"),
    ),
    "bool-vs-str": (
        {True: "EVIL-BOOL", "True": "ok-bool"},
        "{True: 'EVIL-BOOL', 'True': 'ok-bool'}",
        False,
        ("EVIL-BOOL", "ok-bool"),
    ),
    "float-vs-str": (
        {1.5: "EVIL-FLOAT", "1.5": "ok-float"},
        "{1.5: 'EVIL-FLOAT', '1.5': 'ok-float'}",
        False,
        ("EVIL-FLOAT", "ok-float"),
    ),
    "enum-vs-str": (
        {Label.GREEN: "EVIL-ENUM", "visible-enum-text": "ok-enum"},
        "{'visible-enum-text': 'EVIL-ENUM', 'visible-enum-text': 'ok-enum'}",
        False,
        ("EVIL-ENUM", "ok-enum"),
    ),
    "int-enum-vs-str": (
        {Level.HIGH: "EVIL-INTENUM", "4242": "ok-intenum"},
        "{4242: 'EVIL-INTENUM', '4242': 'ok-intenum'}",
        False,
        ("EVIL-INTENUM", "ok-intenum"),
    ),
    "marker-vs-marker": (
        {Opaque(): "EVIL-OBJ", Opaque(): "ok-obj"},
        f"{{{marker(KEY_OPAQUE)}: 'EVIL-OBJ', {marker(KEY_OPAQUE)}: 'ok-obj'}}",
        True,
        ("EVIL-OBJ", "ok-obj"),
    ),
    "marker-vs-str": (
        {Opaque(): "EVIL-MARK", marker(KEY_OPAQUE): "ok-mark"},
        f"{{{marker(KEY_OPAQUE)}: 'EVIL-MARK', '{marker(KEY_OPAQUE)}': 'ok-mark'}}",
        True,
        ("EVIL-MARK", "ok-mark"),
    ),
}
COLLISION_CASES = [
    pytest.param(case, place, id=f"{name}-{place}") for name, case in COLLISIONS.items() for place in PLACES
]


@pytest.mark.parametrize(("case", "place"), COLLISION_CASES)
def test_a_key_text_collision_keeps_both_values_and_the_sibling_visible(case: tuple[Any, ...], place: str) -> None:
    value, _, _, shown = case
    text = stringify_value(PLACES[place][0](value))
    assert all(part in text for part in shown)
    assert place == "alone" or SIBLING in text


@pytest.mark.parametrize(("case", "place"), COLLISION_CASES)
def test_a_key_text_collision_prints_the_python_text_of_every_pair(case: tuple[Any, ...], place: str) -> None:
    value, python_text, _, _ = case
    build, expected = PLACES[place]
    assert stringify_value(build(value)) == expected(python_text)


@pytest.mark.parametrize(("case", "place"), COLLISION_CASES)
def test_a_key_text_collision_flags_the_source_only_when_a_key_printed_the_marker(
    case: tuple[Any, ...], place: str
) -> None:
    value, _, printed_marker, shown = case
    source = flagged(PLACES[place][0](value))
    assert source.unrenderable is printed_marker
    assert all(part in source.text for part in shown)


@pytest.mark.parametrize("place", PLACES)
def test_distinct_key_texts_keep_the_compact_json_form(place: str) -> None:
    source = flagged(PLACES[place][0]({1: "v", "b": SIBLING}))
    assert source.text == stringify_value(PLACES[place][0]({"1": "v", "b": SIBLING}))
    assert source.text.count('"1":"v"') == 1
    assert "'" not in source.text
    assert source.unrenderable is False


def _getter(name: str, result: Any) -> property:
    def get(self: Any) -> Any:
        CALLS.append(name)
        return result

    return property(get)


def _getattribute(self: Any, name: str) -> Any:
    CALLS.append(name)
    return object.__getattribute__(self, name)


def _meta_getattribute(cls: Any, name: str) -> Any:
    CALLS.append(name)
    return EnumMeta.__getattribute__(cls, name)


COUNTING_META = type("CountingMeta", (EnumMeta,), {"__getattribute__": _meta_getattribute})


def enum_member(base: type | None, member: Any, meta: type = EnumMeta, **mixin_attrs: Any) -> Any:
    """Return member A of an Enum built from a mixin with ``mixin_attrs``, then forget the calls building made."""
    mixin = type("Mixin", (base or object,), mixin_attrs)
    cls = types.new_class("Built", (mixin, Enum), {"metaclass": meta}, lambda ns: ns.__setitem__("A", member))
    value = cls.A
    CALLS.clear()
    return value


# id -> (member, the value its getter would return). The stored value is absent, so the member prints its marker.
NO_STORED_VALUE = {
    "int-mixin-property": lambda: (enum_member(int, 5, _value_=_getter("_value_", 999)), "999"),
    "str-mixin-property": lambda: (enum_member(str, "real", _value_=_getter("_value_", "BENIGN")), "BENIGN"),
    "plain-mixin-property": lambda: (enum_member(None, "stored", _value_=_getter("_value_", "BENIGN")), "BENIGN"),
}
NO_STORED_CASES = [
    pytest.param(build, place, id=f"{name}-{place}") for name, build in NO_STORED_VALUE.items() for place in PLACES
]


@pytest.mark.parametrize(("build", "place"), NO_STORED_CASES)
def test_an_enum_member_with_no_stored_value_prints_its_marker_and_runs_no_getter(
    build: Callable[[], tuple[Any, str]], place: str
) -> None:
    member, getter_result = build()
    make, expected = PLACES[place]
    assert stringify_value(make(member)) == expected(marker(member))
    assert getter_result not in stringify_value(make(member))
    assert CALLS == []


@pytest.mark.parametrize(("build", "place"), NO_STORED_CASES)
def test_taint_flags_an_enum_member_with_no_stored_value_and_runs_no_getter(
    build: Callable[[], tuple[Any, str]], place: str
) -> None:
    member, _ = build()
    source = flagged(PLACES[place][0](member))
    assert source.unrenderable is True
    assert marker(member) in source.text
    assert CALLS == []


# id -> (member, the value held in its own storage). Each class hook below would show a value that is not stored.
STORED_VALUE = {
    "int-mixin-dict-property": lambda: (enum_member(int, 7, __dict__=_getter("__dict__", {"_value_": "FAKE"})), 7),
    "str-mixin-dict-property": lambda: (
        enum_member(str, "seven", __dict__=_getter("__dict__", {"_value_": "FAKE"})),
        "seven",
    ),
    "int-mixin-getattribute": lambda: (enum_member(int, 9, __getattribute__=_getattribute), 9),
    "str-mixin-getattribute": lambda: (enum_member(str, "nine", __getattribute__=_getattribute), "nine"),
    "int-metaclass-getattribute": lambda: (enum_member(int, 11, COUNTING_META), 11),
    "str-metaclass-getattribute": lambda: (enum_member(str, "eleven", COUNTING_META), "eleven"),
}
STORED_CASES = [pytest.param(build, id=name) for name, build in STORED_VALUE.items()]


@pytest.mark.parametrize("build", STORED_CASES)
def test_an_enum_member_prints_the_value_from_its_own_storage_and_runs_no_class_code(
    build: Callable[[], tuple[Any, Any]],
) -> None:
    member, stored = build()
    assert stringify_value(member) == stringify_value(stored)
    assert "FAKE" not in stringify_value(member)
    assert CALLS == []


@pytest.mark.parametrize("build", STORED_CASES)
def test_an_enum_member_in_a_container_prints_its_stored_value_and_runs_no_class_code(
    build: Callable[[], tuple[Any, Any]],
) -> None:
    member, stored = build()
    source = flagged([member, SIBLING])
    assert source.text == stringify_value([stored, SIBLING])
    assert source.unrenderable is False
    assert CALLS == []


@pytest.mark.parametrize(
    ("member", "expected"),
    [
        pytest.param(Label.GREEN, "visible-enum-text", id="plain"),
        pytest.param(Level.HIGH, "4242", id="int-enum"),
    ],
)
def test_a_plain_enum_member_still_prints_its_value(member: Enum, expected: str) -> None:
    assert stringify_value(member) == expected
    assert stringify_value([member, SIBLING]) == stringify_value([member.value, SIBLING])
    assert flagged(member).unrenderable is False
