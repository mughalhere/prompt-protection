"""stringify_value allowlist (bead j8o, owner decision 2026-11-24, "A, with safeguards").

Only str, int, float, bool, None, bytes and range keep their own text. Mappings are walked by items,
sized collections by elements, other objects by fields. A one-shot or unsized iterable is never consumed
and prints a fixed marker that names its type. These tests assert properties, never the marker or the
exact object form, because python-dev picks both.
"""

import itertools
from collections import OrderedDict, UserDict, UserList, defaultdict, deque
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from prompt_protection.guard import stringify_value

SECRET = "visible-secret"
SIBLING = "visible-sibling"
FIELD_TEXT = "visible-field"
SAFE_NAMES = {"__dict__", "__slots__"}
TOUCHED: list[str] = []


class Plain:
    def __init__(self) -> None:
        self.secret = SECRET


class Holder:
    def __init__(self, item: Any, sibling: str = SIBLING) -> None:
        self.item = item
        self.sibling = sibling


@dataclass
class DataHolder:
    inner: Any


@dataclass(slots=True)
class SlotsDataHolder:
    inner: Any


class ReprShowsInner:
    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def __repr__(self) -> str:
        return f"ReprShowsInner({self.inner!r})"


class ReprConstant:
    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def __repr__(self) -> str:
        return "constant-repr-text"


class TaggedList(list[Any]):
    def __repr__(self) -> str:
        return f"TaggedList{list.__repr__(self)}"


# Cases 1 and 2: a holder of a plain object must not hide that object's fields behind an object repr.
HOLDERS = {
    "audit-defaultdict": lambda p: defaultdict(list, {"a": p}),
    "audit-dataclass": DataHolder,
    "dataclass-with-slots": SlotsDataHolder,
    "repr-only-type-showing-its-field": ReprShowsInner,
    "repr-only-type-with-a-constant-repr": ReprConstant,
    "user-dict": lambda p: UserDict({"a": p}),
    "mapping-proxy": lambda p: MappingProxyType({"a": p}),
    "user-list": lambda p: UserList([p]),
    "list-subclass-with-its-own-repr": lambda p: TaggedList([p]),
    "set": lambda p: {p},
    "frozenset": lambda p: frozenset({p}),
    "ordered-dict": lambda p: OrderedDict(a=p),
    "deque": lambda p: deque([p]),
    "list": lambda p: [p],
    "dict": lambda p: {"a": p},
    "tuple": lambda p: (p, 1),
}


@pytest.mark.parametrize("build", HOLDERS.values(), ids=HOLDERS.keys())
def test_a_container_or_object_holding_a_plain_object_shows_that_objects_fields(build: Callable[[Any], Any]) -> None:
    text = stringify_value(build(Plain()))
    assert SECRET in text
    assert " object at 0x" not in text


class Unsized:
    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.pulls = 0

    def __iter__(self) -> Iterator[Any]:
        self.pulls += 1
        return iter(())


class Ticker:
    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.pulls = 0

    def __iter__(self) -> "Ticker":
        return self

    def __next__(self) -> int:
        self.pulls += 1
        if self.pulls > 1000:
            raise StopIteration
        return self.pulls


Stream = tuple[Any, Callable[[], Any], Any]


def _generator(tag: str, tmp_path: Path, stack: ExitStack) -> Stream:
    def source() -> Iterator[str]:
        yield f"first-{tag}"
        yield f"second-{tag}"

    gen = source()
    return gen, lambda: next(gen), f"first-{tag}"


def _list_iterator(tag: str, tmp_path: Path, stack: ExitStack) -> Stream:
    it = iter([f"first-{tag}", 2])
    return it, lambda: next(it), f"first-{tag}"


def _count(tag: str, tmp_path: Path, stack: ExitStack) -> Stream:
    counter = itertools.count(ord(tag))
    return counter, lambda: next(counter), ord(tag)


def _file(tag: str, tmp_path: Path, stack: ExitStack) -> Stream:
    content = f"alpha-{tag}\nbeta-{tag}\n"
    path = tmp_path / f"stream-{tag}.txt"
    path.write_text(content, encoding="utf-8")
    handle = stack.enter_context(path.open(encoding="utf-8"))
    return handle, handle.read, content


def _unsized(tag: str, tmp_path: Path, stack: ExitStack) -> Stream:
    stream = Unsized(tag)
    return stream, lambda: stream.pulls, 0


def _ticker(tag: str, tmp_path: Path, stack: ExitStack) -> Stream:
    stream = Ticker(tag)
    return stream, lambda: stream.pulls, 0


STREAMS = {
    "generator": _generator,
    "list-iterator": _list_iterator,
    "itertools-count": _count,
    "open-file": _file,
    "iterable-without-len": _unsized,
    "custom-iterator": _ticker,
}
PLACEMENTS = {
    "alone": lambda s: s,
    "in-a-list": lambda s: [s, SIBLING],
    "in-a-dict": lambda s: {"stream": s, "sibling": SIBLING},
    "in-an-object": Holder,
}


@pytest.fixture
def stack() -> Iterator[ExitStack]:
    with ExitStack() as opened:
        yield opened


@pytest.mark.usefixtures("deadline")
@pytest.mark.parametrize("place", PLACEMENTS.values(), ids=PLACEMENTS.keys())
@pytest.mark.parametrize("make", STREAMS.values(), ids=STREAMS.keys())
def test_a_one_shot_or_unsized_iterable_is_not_consumed_and_its_marker_names_its_type(
    make: Callable[[str, Path, ExitStack], Stream], place: Callable[[Any], Any], tmp_path: Path, stack: ExitStack
) -> None:
    value, read, expected = make("a", tmp_path, stack)
    text = stringify_value(place(value))
    assert type(value).__name__ in text
    assert read() == expected
    if place is not PLACEMENTS["alone"]:
        assert SIBLING in text


@pytest.mark.usefixtures("deadline")
@pytest.mark.parametrize("make", STREAMS.values(), ids=STREAMS.keys())
def test_the_marker_of_a_one_shot_or_unsized_iterable_is_fixed_for_its_type(
    make: Callable[[str, Path, ExitStack], Stream], tmp_path: Path, stack: ExitStack
) -> None:
    first, _, _ = make("a", tmp_path, stack)
    second, _, _ = make("b", tmp_path, stack)
    text = stringify_value(first)
    assert stringify_value(second) == text
    assert " at 0x" not in text


class _Trapped:
    __slots__ = ()

    @property
    def raises(self) -> str:
        TOUCHED.append("raises")
        raise RuntimeError("property read")

    @property
    def counts(self) -> str:
        TOUCHED.append("counts")
        return "from-property"

    def __getattr__(self, name: str) -> Any:
        if name in SAFE_NAMES:
            raise AttributeError(name)
        TOUCHED.append(name)
        raise RuntimeError(f"getattr {name}")


class HostileDict(_Trapped):
    def __init__(self) -> None:
        self.visible = FIELD_TEXT


class HostileSlots(_Trapped):
    __slots__ = ("visible",)

    def __init__(self) -> None:
        self.visible = FIELD_TEXT


@pytest.fixture
def touched() -> list[str]:
    del TOUCHED[:]
    return TOUCHED


@pytest.mark.parametrize("wrap", [lambda o: o, lambda o: {"o": o}], ids=["alone", "in-a-dict"])
@pytest.mark.parametrize("cls", [HostileDict, HostileSlots], ids=["dict-instance", "slots-instance"])
def test_an_object_is_walked_without_reading_a_property_or_any_name_but_its_fields(
    cls: type, wrap: Callable[[Any], Any], touched: list[str]
) -> None:
    text = stringify_value(wrap(cls()))
    assert FIELD_TEXT in text
    assert touched == []


LEAVES = [
    pytest.param(b"ab", id="bytes"),
    pytest.param(2.5, id="float"),
    pytest.param(float("inf"), id="float-inf"),
    pytest.param(True, id="bool"),
    pytest.param(None, id="none"),
    pytest.param(range(2, 9, 3), id="range"),
    pytest.param(7, id="int"),
]


@pytest.mark.parametrize("leaf", LEAVES)
def test_an_allowlisted_leaf_keeps_its_own_python_text_inside_an_object(leaf: Any) -> None:
    text = stringify_value(Holder(leaf))
    assert repr(leaf) in text
    assert SIBLING in text


@pytest.mark.parametrize("leaf", [pytest.param(b"ab", id="bytes"), pytest.param(range(2, 9, 3), id="range")])
def test_a_bytes_or_range_leaf_in_a_list_keeps_its_own_python_text(leaf: Any) -> None:
    assert stringify_value([leaf, SIBLING]) == f"[{leaf!r}, '{SIBLING}']"


class Tag(str):
    pass


class Level(IntEnum):
    HIGH = 4242


class Count(int):
    pass


class Meters(float):
    pass


# The decision lists exact types and is silent on subclasses, so only the value's visibility is asserted.
SUBCLASS_LEAVES = [
    pytest.param(Tag("visible-tag-value"), "visible-tag-value", id="str-subclass"),
    pytest.param(Level.HIGH, "4242", id="int-enum"),
    pytest.param(Count(31337), "31337", id="int-subclass"),
    pytest.param(Meters(2.5), "2.5", id="float-subclass"),
]


@pytest.mark.parametrize(("leaf", "shown"), SUBCLASS_LEAVES)
def test_a_subclass_of_an_allowlisted_type_keeps_its_value_visible_inside_an_object(leaf: Any, shown: str) -> None:
    text = stringify_value(Holder(leaf))
    assert shown in text
    assert " object at 0x" not in text
