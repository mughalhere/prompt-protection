"""Memory lineage and trust labels (twin of src/guard/memory.ts, plan D2, D3, D40).

A ``MemoryEntry`` is a wire dict with the JS keys (D3). A lineage edge on a guard object is a
``LineageEdge`` and exposes ``from_`` (D2). The guard converts between the two at the memory boundary.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypedDict, TypeGuard

from prompt_protection._result import JsResult
from prompt_protection.guard._types import SourceInjection, TaintedSource

__all__ = [
    "MIN_EDGE",
    "STRONG_EDGE",
    "TRUST_LABEL_RANK",
    "LineageEdge",
    "LineageKind",
    "MemoryEntry",
    "MemoryReadResult",
    "MemoryWriteResult",
    "TrustLabel",
    "derive_label",
    "is_memory_entry",
    "max_label",
    "rank_of",
]

TrustLabel = str
LineageKind = str

TRUST_LABEL_RANK: dict[str, int] = {"system": 0, "user": 1, "tool": 2, "untrusted": 3, "blocked": 4}

_UNTRUSTED_RANK = 3

STRONG_EDGE = 0.5
MIN_EDGE = 0.1


def rank_of(label: str) -> int:
    """Return the rank of a label, higher is less trusted. An unknown label ranks as ``untrusted``."""
    return TRUST_LABEL_RANK.get(label, _UNTRUSTED_RANK)


def max_label(first: str, *rest: str) -> str:
    """Return the least trusted label. The earlier one wins a tie."""
    out = first
    for label in rest:
        if rank_of(label) > rank_of(out):
            out = label
    return out


@dataclass(frozen=True, kw_only=True)
class LineageEdge(JsResult):
    """A value came from ``from_``, a source or entry id. An edge at or above ``STRONG_EDGE`` propagates its label."""

    from_: str
    kind: str
    strength: float


_WireEdge = TypedDict("_WireEdge", {"from": str, "kind": str, "strength": float})


class _MemoryEntryRequired(TypedDict):
    v: int
    id: str
    value: str
    label: str
    sourceIds: list[str]
    lineage: list[_WireEdge]
    injection: dict[str, Any]
    rulesVersion: str
    turn: int
    ts: str


class MemoryEntry(_MemoryEntryRequired, total=False):
    """The wire form of a stored memory. ``key`` is absent when none was given, and ``sig`` is reserved."""

    key: str
    sig: str


@dataclass(frozen=True, kw_only=True)
class MemoryWriteResult(JsResult):
    """``store`` is false when the policy rejects the entry. ``entry`` is the wire record to persist."""

    source: TaintedSource
    action: str
    store: bool
    entry: MemoryEntry


@dataclass(frozen=True, kw_only=True)
class MemoryReadResult(JsResult):
    """``label`` is the highest label read. ``injection`` is the highest score, re-scored under the current rules."""

    sources: list[TaintedSource]
    label: str
    edges: list[LineageEdge]
    injection: SourceInjection


def derive_label(edges: Sequence[LineageEdge], label_of: Callable[[str], str | None], own: str) -> str:
    """Return the max label over strong edges, then the max with ``own``."""
    out = own
    for edge in edges:
        if edge.strength < STRONG_EDGE:
            continue
        parent = label_of(edge.from_)
        if parent is not None and rank_of(parent) > rank_of(out):
            out = parent
    return out


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_edge(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and isinstance(value.get("from"), str)
        and isinstance(value.get("kind"), str)
        and _is_number(value.get("strength"))
    )


def is_memory_entry(value: object) -> TypeGuard[MemoryEntry]:
    """Check app-supplied JSON structurally. Anything else is rejected rather than trusted."""
    if not isinstance(value, Mapping) or not _is_number(value.get("v")) or value["v"] != 1:
        return False
    if not all(isinstance(value.get(k), str) for k in ("id", "value", "label")):
        return False
    source_ids, lineage, injection = value.get("sourceIds"), value.get("lineage"), value.get("injection")
    if not isinstance(source_ids, list) or not all(isinstance(s, str) for s in source_ids):
        return False
    if not isinstance(lineage, list) or not all(_is_edge(e) for e in lineage):
        return False
    if not isinstance(injection, Mapping) or not _is_number(injection.get("score")):
        return False
    if not isinstance(injection.get("action"), str):
        return False
    return (
        isinstance(value.get("rulesVersion"), str)
        and _is_number(value.get("turn"))
        and isinstance(value.get("ts"), str)
    )
