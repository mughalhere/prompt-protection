"""stringify_value stdlib leaves (bead j8o, owner decision 2026-11-25, option A).

complex, Decimal, Fraction, date, time, datetime, timedelta, timezone, UUID and PurePath, and their subclasses,
print through their base type's str. An Enum member prints its value, a re.Pattern its pattern, and a function,
method or class its __qualname__. No __str__ or __repr__ override hides any of them. Beside a sibling, the form
(quoting, key position) is not fixed, so those placements assert that the text and the sibling are visible.
"""

import json
import re
from collections.abc import Callable
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from enum import Enum, IntEnum
from fractions import Fraction
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Any
from uuid import UUID

import pytest

from prompt_protection.guard import stringify_value

SIBLING = "visible-sibling"
SECRET = "visible-secret"
UUID_TEXT = "12345678-1234-5678-1234-567812345678"


class Holder:
    def __init__(self, item: Any, sibling: str = SIBLING) -> None:
        self.item = item
        self.sibling = sibling


class Plain:
    def __init__(self) -> None:
        self.secret = SECRET


class Greeter:
    class Inner:
        pass

    def visible_method(self) -> None:
        pass


def visible_function() -> None:
    pass


class Veiling(type):
    def __str__(cls) -> str:
        return "hidden"

    def __repr__(cls) -> str:
        return "hidden"


class Shown(metaclass=Veiling):
    pass


def hiding(base: type, *args: Any) -> Any:
    """Build an instance of a subclass of ``base`` whose __str__ and __repr__ both say "hidden"."""
    members = {"__str__": lambda self: "hidden", "__repr__": lambda self: "hidden"}
    return type(f"Hidden{base.__name__}", (base,), members)(*args)


def base_str(owner: type) -> Callable[[Any], str]:
    return lambda value: owner.__str__(value)


def complex_text(value: Any) -> str:
    """complex has no __str__ of its own, so object.__str__ would call a subclass's __repr__."""
    return complex.__repr__(value)


def qualname(value: Any) -> str:
    return str(value.__qualname__)


def pattern_of(value: Any) -> str:
    return str(value.pattern)


def row(case_id: str, value: Any, expected: str, derive: Callable[[Any], str]) -> Any:
    return pytest.param(value, expected, derive, id=case_id)


# The expected text is the owner type's own __str__, pinned as a literal and re-derived by the first test.
# A datetime is also a date, so its row has a time part that only the datetime form prints.
CASES = [
    row("complex", complex(2, 1), "(2+1j)", complex_text),
    row("complex-negative-imaginary", complex(1.5, -2), "(1.5-2j)", complex_text),
    row("decimal", Decimal("1.50"), "1.50", base_str(Decimal)),
    row("decimal-exponent", Decimal("1E+3"), "1E+3", base_str(Decimal)),
    row("fraction", Fraction(1, 3), "1/3", base_str(Fraction)),
    row("fraction-negative", Fraction(-22, 7), "-22/7", base_str(Fraction)),
    row("date", date(2020, 1, 2), "2020-01-02", base_str(date)),
    row("time", time(1, 2, 3), "01:02:03", base_str(time)),
    row("time-microsecond", time(1, 2, 3, 4), "01:02:03.000004", base_str(time)),
    row("datetime-naive", datetime(2020, 1, 2, 3, 4, 5), "2020-01-02 03:04:05", base_str(datetime)),
    row("datetime-microsecond", datetime(2020, 1, 2, 3, 4, 5, 6), "2020-01-02 03:04:05.000006", base_str(datetime)),
    row(
        "datetime-utc",
        datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "2020-01-02 03:04:05+00:00",
        base_str(datetime),
    ),
    row(
        "datetime-fixed-offset",
        datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        "2020-01-02 03:04:05+05:30",
        base_str(datetime),
    ),
    row("timedelta", timedelta(days=1, hours=2), "1 day, 2:00:00", base_str(timedelta)),
    row("timedelta-negative", timedelta(days=-1, hours=2), "-1 day, 2:00:00", base_str(timedelta)),
    row("timezone-utc", timezone.utc, "UTC", base_str(timezone)),
    row("timezone-offset", timezone(timedelta(hours=5, minutes=30)), "UTC+05:30", base_str(timezone)),
    row("timezone-named", timezone(timedelta(hours=1), "visible-zone"), "visible-zone", base_str(timezone)),
    row("uuid", UUID(UUID_TEXT), UUID_TEXT, base_str(UUID)),
    row("pure-posix-path", PurePosixPath("/visible/path/file.txt"), "/visible/path/file.txt", base_str(PurePath)),
    row("pure-windows-path", PureWindowsPath("C:/visible/path"), "C:\\visible\\path", base_str(PurePath)),
    row("complex-subclass-hiding-str", hiding(complex, 2, 1), "(2+1j)", complex_text),
    row("decimal-subclass-hiding-str", hiding(Decimal, "1.50"), "1.50", base_str(Decimal)),
    row("fraction-subclass-hiding-str", hiding(Fraction, 1, 3), "1/3", base_str(Fraction)),
    row("date-subclass-hiding-str", hiding(date, 2020, 1, 2), "2020-01-02", base_str(date)),
    row("time-subclass-hiding-str", hiding(time, 1, 2, 3), "01:02:03", base_str(time)),
    row(
        "datetime-subclass-hiding-str", hiding(datetime, 2020, 1, 2, 3, 4, 5), "2020-01-02 03:04:05", base_str(datetime)
    ),
    row("timedelta-subclass-hiding-str", hiding(timedelta, 1, 7200), "1 day, 2:00:00", base_str(timedelta)),
    row("uuid-subclass-hiding-str", hiding(UUID, UUID_TEXT), UUID_TEXT, base_str(UUID)),
    row("posix-path-subclass-hiding-str", hiding(PurePosixPath, "/visible/path"), "/visible/path", base_str(PurePath)),
    row("windows-path-subclass-hiding-str", hiding(PureWindowsPath, "C:/visible"), "C:\\visible", base_str(PurePath)),
    row("pattern", re.compile("visible-pattern"), "visible-pattern", pattern_of),
    row(
        "pattern-with-flags", re.compile("visible-(flag|pattern)", re.IGNORECASE), "visible-(flag|pattern)", pattern_of
    ),
    row("function", visible_function, "visible_function", qualname),
    row("method-unbound", Greeter.visible_method, "Greeter.visible_method", qualname),
    row("method-bound", Greeter().visible_method, "Greeter.visible_method", qualname),
    row("builtin-function", len, "len", qualname),
    row("builtin-method", [].append, "list.append", qualname),
    row("class", Greeter, "Greeter", qualname),
    row("nested-class", Greeter.Inner, "Greeter.Inner", qualname),
    row("class-with-a-metaclass-hiding-str", Shown, "Shown", qualname),
]

PLACES: dict[str, Callable[[Any], Any]] = {
    "listed": lambda v: [v, SIBLING],
    "in-an-object": Holder,
    "dict-value": lambda v: {"key": v, "sibling": SIBLING},
    "dict-key": lambda v: {v: SIBLING},
}


def visible(text: str, shown: str) -> bool:
    """True when ``shown`` is in ``text`` as is or as the body of its quoted (backslash-escaped) form."""
    return shown in text or repr(shown)[1:-1] in text


def assert_shows(text: str, shown: str) -> None:
    assert visible(text, shown)
    assert SIBLING in text
    assert " object at 0x" not in text
    assert "hidden" not in text


def accepted_texts(place: str, shown: str) -> set[str]:
    """The container forms already pinned elsewhere, with the leaf as its bare text or as a quoted string."""
    leaf = {shown, repr(shown)}
    sibling = f"'{SIBLING}'"
    if place == "listed":
        return {f"[{x}, {sibling}]" for x in leaf}
    if place == "in-an-object":
        return {f"Holder(item={x}, sibling={sibling})" for x in leaf}
    if place == "dict-value":
        return {f"{{'key': {x}, 'sibling': {sibling}}}" for x in leaf}
    return {f"{{{x}: {sibling}}}" for x in leaf} | {f'{{{json.dumps(shown)}:"{SIBLING}"}}'}


@pytest.mark.parametrize(("value", "expected", "derive"), CASES)
def test_the_pinned_text_is_what_the_base_type_gives(value: Any, expected: str, derive: Callable[[Any], str]) -> None:
    assert derive(value) == expected


@pytest.mark.parametrize(("value", "expected", "derive"), CASES)
def test_a_stdlib_leaf_alone_prints_its_base_text(value: Any, expected: str, derive: Callable[[Any], str]) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize("place", PLACES)
@pytest.mark.parametrize(("value", "expected", "derive"), CASES)
def test_a_stdlib_leaf_beside_a_sibling_shows_both(
    value: Any, expected: str, derive: Callable[[Any], str], place: str
) -> None:
    assert stringify_value(PLACES[place](value)) in accepted_texts(place, expected)


@pytest.mark.parametrize("place", ["alone", *PLACES])
def test_a_bytes_pattern_shows_its_pattern_text(place: str) -> None:
    compiled = re.compile(b"visible-bytes-pattern")
    value = compiled if place == "alone" else PLACES[place](compiled)
    assert "visible-bytes-pattern" in stringify_value(value)


class Label(Enum):
    GREEN = "visible-enum-text"


class Level(IntEnum):
    HIGH = 4242


class Tint(str, Enum):
    RED = "visible-tint"


class Point(Enum):
    ORIGIN = (1, "visible-tuple")


class Vault(Enum):
    BOX = Plain()


class Veiled(Enum):
    COVER = "visible-veiled"

    def __str__(self) -> str:
        return "hidden"

    def __repr__(self) -> str:
        return "hidden"


class Wrap(Enum):
    INNER = Label.GREEN


# (member, text of its value alone, a fragment of that text). The values keep the forms the allowlist already fixes.
ENUMS = [
    pytest.param(Label.GREEN, "visible-enum-text", "visible-enum-text", id="str-value"),
    pytest.param(Level.HIGH, "4242", "4242", id="int-enum"),
    pytest.param(Tint.RED, "visible-tint", "visible-tint", id="str-mixin-enum"),
    pytest.param(Point.ORIGIN, '[1,"visible-tuple"]', "visible-tuple", id="tuple-value"),
    pytest.param(Vault.BOX, "Plain(secret='visible-secret')", SECRET, id="plain-object-value"),
    pytest.param(Veiled.COVER, "visible-veiled", "visible-veiled", id="overridden-str-and-repr"),
    pytest.param(Wrap.INNER, "visible-enum-text", "visible-enum-text", id="member-of-another-enum-as-value"),
]


@pytest.mark.parametrize(("member", "alone", "fragment"), ENUMS)
def test_an_enum_member_alone_prints_the_text_of_its_value(member: Enum, alone: str, fragment: str) -> None:
    assert stringify_value(member) == alone
    assert alone == stringify_value(member.value)


@pytest.mark.parametrize("place", ["listed", "in-an-object", "dict-value"])
@pytest.mark.parametrize(("member", "alone", "fragment"), ENUMS)
def test_an_enum_member_in_a_container_prints_as_its_value_would(
    member: Enum, alone: str, fragment: str, place: str
) -> None:
    assert stringify_value(PLACES[place](member)) == stringify_value(PLACES[place](member.value))


@pytest.mark.parametrize(("member", "alone", "fragment"), ENUMS)
def test_an_enum_member_as_a_mapping_key_shows_its_value_and_the_sibling(
    member: Enum, alone: str, fragment: str
) -> None:
    assert_shows(stringify_value(PLACES["dict-key"](member)), fragment)
