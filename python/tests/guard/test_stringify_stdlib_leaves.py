"""stringify_value stdlib leaves.

complex, Decimal, Fraction, date, time, datetime, timedelta, timezone, UUID and PurePath, and their subclasses,
print through their base type's str. An Enum member prints its value, a re.Pattern its pattern, and a function,
method or class its __qualname__. No __str__ or __repr__ override hides any of them. Beside a sibling in an
exact container, the form (quoting, key position) is not fixed. Inside any other object the object prints a marker.
"""

import datetime as dt
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
HOLDER_MARKER = "<Holder not rendered>"
PLAIN_MARKER = "<Plain not rendered>"
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
EXACT_PLACES = [place for place in PLACES if place != "in-an-object"]


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
    if place == "dict-value":
        return {f"{{'key': {x}, 'sibling': {sibling}}}" for x in leaf}
    return {f"{{{x}: {sibling}}}" for x in leaf} | {f'{{{json.dumps(shown)}:"{SIBLING}"}}'}


@pytest.mark.parametrize(("value", "expected", "derive"), CASES)
def test_the_pinned_text_is_what_the_base_type_gives(value: Any, expected: str, derive: Callable[[Any], str]) -> None:
    assert derive(value) == expected


@pytest.mark.parametrize(("value", "expected", "derive"), CASES)
def test_a_stdlib_leaf_alone_prints_its_base_text(value: Any, expected: str, derive: Callable[[Any], str]) -> None:
    assert stringify_value(value) == expected


@pytest.mark.parametrize("place", EXACT_PLACES)
@pytest.mark.parametrize(("value", "expected", "derive"), CASES)
def test_a_stdlib_leaf_beside_a_sibling_shows_both(
    value: Any, expected: str, derive: Callable[[Any], str], place: str
) -> None:
    assert stringify_value(PLACES[place](value)) in accepted_texts(place, expected)


IN_AN_OBJECT = [pytest.param(case.values[0], case.values[1], id=case.id) for case in CASES]
IN_AN_OBJECT.append(pytest.param(re.compile(b"visible-bytes-pattern"), "visible-bytes-pattern", id="bytes-pattern"))


@pytest.mark.parametrize(("value", "shown"), IN_AN_OBJECT)
def test_a_stdlib_leaf_inside_an_object_prints_the_objects_marker_and_neither_the_leaf_nor_its_sibling(
    value: Any, shown: str
) -> None:
    text = stringify_value(Holder(value))
    assert text == HOLDER_MARKER
    assert shown not in text
    assert SIBLING not in text


@pytest.mark.parametrize("place", ["alone", *EXACT_PLACES])
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
    pytest.param(Vault.BOX, PLAIN_MARKER, PLAIN_MARKER, id="plain-object-value"),
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


def placed(value: Any, place: str) -> Any:
    return value if place == "alone" else PLACES[place](value)


VAULT_TEXT = {
    "alone": PLAIN_MARKER,
    "listed": f"[{PLAIN_MARKER}, '{SIBLING}']",
    "dict-value": f"{{'key': {PLAIN_MARKER}, 'sibling': '{SIBLING}'}}",
    "dict-key": f'{{"{PLAIN_MARKER}":"{SIBLING}"}}',
}


@pytest.mark.parametrize("place", VAULT_TEXT)
def test_an_enum_member_whose_value_is_a_plain_object_prints_that_objects_marker_and_not_its_fields(place: str) -> None:
    text = stringify_value(placed(Vault.BOX, place))
    assert text == VAULT_TEXT[place]
    assert SECRET not in text


def assert_prints(value: Any, expected: str, place: str) -> None:
    """The real value prints: exactly alone, or in the pinned list forms beside the sibling. "hidden" never shows."""
    text = stringify_value(placed(value, place))
    assert text == expected if place == "alone" else text in accepted_texts(place, expected)
    assert "hidden" not in text


ALONE_OR_LISTED = ["alone", "listed"]


def overriding(base: type, names: list[str], *args: Any) -> Any:
    """Build an instance of a subclass of ``base`` whose methods ``names`` all return "hidden"."""
    members = {name: (lambda self, *a, **k: "hidden") for name in names}
    return type(f"Over{base.__name__}", (base,), members)(*args)


MOMENTS = [
    pytest.param(date, (2020, 1, 2), "2020-01-02", id="date"),
    pytest.param(time, (1, 2, 3), "01:02:03", id="time"),
    pytest.param(datetime, (2020, 1, 2, 3, 4, 5), "2020-01-02 03:04:05", id="datetime"),
]


@pytest.mark.parametrize("place", ALONE_OR_LISTED)
@pytest.mark.parametrize("names", [["isoformat"], ["isoformat", "__str__"]], ids=["isoformat", "isoformat-and-str"])
@pytest.mark.parametrize(("base", "args", "expected"), MOMENTS)
def test_a_moment_subclass_overriding_isoformat_still_prints_its_real_value(
    base: type, args: tuple[int, ...], expected: str, names: list[str], place: str
) -> None:
    assert_prints(overriding(base, names, *args), expected, place)


class Zone(dt.tzinfo):
    """A zone that counts every hook call, and raises from each when ``fail`` is set."""

    def __init__(self, fail: bool) -> None:
        self.calls = 0
        self.fail = fail

    def _hit(self) -> None:
        self.calls += 1
        if self.fail:
            raise RuntimeError("zone hook ran")

    def utcoffset(self, when: dt.datetime | None) -> dt.timedelta:
        self._hit()
        return timedelta(hours=9)

    def dst(self, when: dt.datetime | None) -> dt.timedelta:
        self._hit()
        return timedelta(0)

    def tzname(self, when: dt.datetime | None) -> str:
        self._hit()
        return "hidden"


ZONED = [
    pytest.param(lambda zone: datetime(2020, 1, 2, 3, 4, 5, tzinfo=zone), "2020-01-02 03:04:05", id="datetime"),
    pytest.param(lambda zone: time(1, 2, 3, tzinfo=zone), "01:02:03", id="time"),
]


# Measured at GREEN7: a custom tzinfo's offset is dropped, so only the wall-clock fields print.
@pytest.mark.parametrize("place", ALONE_OR_LISTED)
@pytest.mark.parametrize("fail", [False, True], ids=["counting-zone", "raising-zone"])
@pytest.mark.parametrize(("build", "expected"), ZONED)
def test_a_custom_tzinfo_runs_no_user_code_and_its_wall_clock_fields_print(
    build: Callable[[Zone], Any], expected: str, fail: bool, place: str
) -> None:
    zone = Zone(fail)
    assert_prints(build(zone), expected, place)
    assert zone.calls == 0


def shadowing(base: type, name: str, wrong: Any) -> property:
    """A property that reads ``wrong`` and still writes to the base attribute, so the real value is stored."""
    attribute = next(vars(owner)[name] for owner in base.__mro__ if name in vars(owner))
    return property(lambda self: wrong, lambda self, value: attribute.__set__(self, value))


SHADOWS = [
    pytest.param(Fraction, "_numerator", 99, (1, 3), "1/3", id="fraction-numerator"),
    pytest.param(Fraction, "_denominator", 7, (1, 3), "1/3", id="fraction-denominator"),
    pytest.param(UUID, "int", 5, (UUID_TEXT,), UUID_TEXT, id="uuid-int"),
    pytest.param(PurePosixPath, "_str", "hidden/wrong", ("/visible/path",), "/visible/path", id="posix-path-_str"),
    pytest.param(PurePosixPath, "drive", "Z:", ("/visible/path",), "/visible/path", id="posix-path-drive"),
    pytest.param(PureWindowsPath, "_str", "hidden\\wrong", ("C:/visible",), "C:\\visible", id="windows-path-_str"),
    pytest.param(PureWindowsPath, "drive", "Z:", ("C:/visible",), "C:\\visible", id="windows-path-drive"),
]


@pytest.mark.parametrize("place", ALONE_OR_LISTED)
@pytest.mark.parametrize(("base", "name", "wrong", "args", "expected"), SHADOWS)
def test_a_subclass_shadowing_a_private_name_of_its_base_still_prints_the_real_value(
    base: type, name: str, wrong: Any, args: tuple[Any, ...], expected: str, place: str
) -> None:
    value = type(f"Shadow{base.__name__}", (base,), {name: shadowing(base, name, wrong)})(*args)
    assert_prints(value, expected, place)


QUALNAME_READS: list[str] = []


class QualnameSpy(type):
    def __getattribute__(cls, name: str) -> Any:
        if name == "__qualname__":
            QUALNAME_READS.append(name)
            return "hidden"
        return super().__getattribute__(name)


class Spied(metaclass=QualnameSpy):
    pass


@pytest.mark.parametrize("place", ALONE_OR_LISTED)
def test_a_class_with_a_metaclass_hooking_qualname_prints_the_real_name_and_the_hook_is_not_called(place: str) -> None:
    QUALNAME_READS.clear()
    assert_prints(Spied, "Spied", place)
    assert QUALNAME_READS == []
