"""Taint handoff wire form and checks (twin of src/guard/handoff.ts).

A ``TaintHandoff`` is a plain dict with the JS keys. Lineage edges inside it keep the key ``from``. A guard
holds them as ``LineageEdge`` objects, except an item that is not exactly a well-formed edge, kept as received.
"""

import copy
from collections.abc import Mapping, Sequence
from typing import Any, Literal, TypedDict, TypeGuard

from prompt_protection.guard.memory import LineageEdge

__all__ = [
    "HandoffError",
    "HandoffSource",
    "TaintHandoff",
    "assert_taint_handoff",
    "is_taint_handoff",
]


class HandoffSource(TypedDict):
    id: str
    tool: str
    text: str
    label: str
    injection: dict[str, Any]
    turn: int
    lineage: list[Any]


class TaintHandoff(TypedDict):
    """Taint state a parent guard passes to a sub-agent's guard (``Guard.handoff`` to ``Guard.absorb``)."""

    v: Literal[1]
    depth: int
    turn: int
    sources: list[HandoffSource]
    trustedIdentifiers: list[str]


class HandoffError(TypeError):
    """Raised for anything but a well-formed v1 handoff."""


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_source(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and all(isinstance(value.get(k), str) for k in ("id", "tool", "text", "label"))
        and isinstance(value.get("injection"), Mapping)
        and _is_number(value.get("turn"))
        and isinstance(value.get("lineage"), list)
    )


def is_taint_handoff(value: object) -> TypeGuard[TaintHandoff]:
    """Check app-supplied JSON structurally. ``v`` must equal 1 and the lists must be lists."""
    if not isinstance(value, Mapping) or not _is_number(value.get("v")) or value["v"] != 1:
        return False
    sources, trusted = value.get("sources"), value.get("trustedIdentifiers")
    return (
        _is_number(value.get("depth"))
        and _is_number(value.get("turn"))
        and isinstance(sources, list)
        and all(_is_source(s) for s in sources)
        and isinstance(trusted, list)
        and all(isinstance(s, str) for s in trusted)
    )


def assert_taint_handoff(value: object) -> None:
    """Raise ``HandoffError`` on anything but a well-formed v1 handoff. A guard never absorbs what it cannot read."""
    if not is_taint_handoff(value):
        raise HandoffError("not a v1 TaintHandoff")


class _RawEdge:
    """A lineage item kept as received, so a handoff gives it back unchanged."""

    __slots__ = ("wire",)

    def __init__(self, wire: object) -> None:
        self.wire = wire

    @property
    def from_(self) -> str:
        origin = self.wire.get("from") if isinstance(self.wire, Mapping) else None
        if not isinstance(origin, str):
            raise TypeError("lineage edge without a string 'from'")
        return origin


def _is_edge(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and isinstance(value.get("from"), str)
        and isinstance(value.get("kind"), str)
        and _is_number(value.get("strength"))
    )


def _lineage_from_wire(items: Sequence[Any]) -> list[LineageEdge | _RawEdge]:
    return [
        LineageEdge(from_=e["from"], kind=e["kind"], strength=e["strength"])
        if _is_edge(e) and len(e) == 3
        else _RawEdge(copy.deepcopy(e))
        for e in items
    ]


def _lineage_to_wire(edges: Sequence[Any] | None) -> list[Any]:
    return [
        copy.deepcopy(e.wire) if isinstance(e, _RawEdge) else {"from": e.from_, "kind": e.kind, "strength": e.strength}
        for e in edges or ()
    ]
