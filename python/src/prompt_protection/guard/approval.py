"""Approval cards and the approval store (twin of src/guard/approval.ts, plan D1, D2, D7, D40).

A card carries the canonical text of the call it asks about. ``confirm`` marks it approved, and a later
check approves a call only when the canonical text is equal. Records are single-use and expire by ``ttl_ms``.
"""

import sys
import time
from argparse import Namespace
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date, timedelta, timezone
from datetime import time as day_time
from decimal import Decimal
from enum import Enum
from fractions import Fraction
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network
from pathlib import PurePath
from types import GetSetDescriptorType, MemberDescriptorType, ModuleType, SimpleNamespace
from typing import Any, Literal, Protocol, TypedDict
from uuid import UUID

from prompt_protection._js import js_number_str, utf16_len, utf16_slice
from prompt_protection.guard._types import GuardDecision, ToolCall
from prompt_protection.guard.provenance import _MAX_LEAF_DEPTH, DESTINATION_KEYS, _js_key_order, key_of

__all__ = [
    "ApprovalCard",
    "ApprovalField",
    "ApprovalFieldKind",
    "ApprovalLookup",
    "ApprovalMismatchCode",
    "ApprovalMismatchError",
    "ApprovalOptions",
    "ApprovalRecord",
    "ApprovalRendered",
    "ApprovalState",
    "ApprovalStatus",
    "ApprovalStore",
    "DEFAULT_APPROVAL_MAX",
    "DEFAULT_APPROVAL_TTL_MS",
    "create_approval_store",
    "render_approval_card",
]

DEFAULT_APPROVAL_TTL_MS = 10 * 60 * 1000
DEFAULT_APPROVAL_MAX = 64

ApprovalStatus = Literal["approved", "mismatch", "expired"]
ApprovalFieldKind = Literal["destination", "payload", "other"]
ApprovalMismatchCode = Literal["digest", "unknown-id", "expired"]

_PAYLOAD_KEYS = frozenset("body content text message command cmd script payload data html code query sql".split())
_MAX_FIELD_UNITS = 200
_PAYLOAD_UNITS = 64


class ApprovalMismatchError(Exception):
    """``confirm`` refused: ``code`` is ``unknown-id``, ``digest`` or ``expired``, and ``id`` is the card id."""

    def __init__(self, code: ApprovalMismatchCode, id: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.id = id


@dataclass
class ApprovalRecord:
    """What the store keeps per card. ``canonical_args`` is compared as a string, never hashed."""

    id: str
    tool_name: str
    canonical_args: str
    digest: str
    created_at: int
    expires_at: int
    tool_call_id: str | None = None
    confirmed_at: int | None = None
    by: str | None = None
    used_at: int | None = None


@dataclass(frozen=True)
class ApprovalState:
    """What the check pipeline learned about a call from the store."""

    id: str
    status: ApprovalStatus


@dataclass(frozen=True)
class ApprovalField:
    """One scalar argument. ``tainted`` is true when a flow landed on ``path``."""

    path: str
    value: str
    tainted: bool
    kind: ApprovalFieldKind
    source_tool: str | None = None


@dataclass(frozen=True)
class ApprovalRendered:
    title: str
    risk: Literal["low", "medium", "high"]
    reasons: list[str]
    summary: str
    fields: list[ApprovalField]


@dataclass(kw_only=True)
class ApprovalCard:
    """What a UI shows. It echoes ``digest`` back to ``confirm``. ``created_at`` is wall-clock ISO text."""

    id: str
    digest: str
    canonical_args: str
    tool_name: str
    tool_call_id: str | None = None
    sink: str
    decision: GuardDecision
    rendered: ApprovalRendered
    created_at: str
    expires_at: str


class ApprovalOptions(TypedDict, total=False):
    """``ttl_ms`` defaults to 10 minutes and ``max_pending`` to 64. ``now`` returns integer milliseconds."""

    ttl_ms: int
    max_pending: int
    now: Callable[[], int]


class ApprovalLookup(Protocol):
    """The part of the store the check pipeline reads: ``lookup`` before policies, ``consume`` after."""

    def lookup(self, call: ToolCall, canonical_args: str) -> ApprovalState | None: ...

    def consume(self, approval_id: str) -> None: ...


class ApprovalStore(ApprovalLookup, Protocol):
    def issue(self, card: ApprovalCard) -> ApprovalRecord: ...

    def confirm(self, id: str, digest: str, by: str | None = None) -> ApprovalRecord: ...

    def get(self, id: str) -> ApprovalRecord | None: ...

    @property
    def size(self) -> int: ...


def _wall_ms() -> int:
    return time.time_ns() // 1_000_000


class _Store:
    def __init__(self, ttl_ms: int, max_pending: int, now: Callable[[], int]) -> None:
        self._ttl = ttl_ms
        self._max = max_pending
        self._now = now
        self._records: dict[str, ApprovalRecord] = {}
        self._by_call_id: dict[str, str] = {}

    @property
    def size(self) -> int:
        return len(self._records)

    def get(self, id: str) -> ApprovalRecord | None:
        return self._records.get(id)

    def _evict(self) -> None:
        while self._records and len(self._records) > self._max:
            oldest = next(iter(self._records))
            rec = self._records.pop(oldest)
            if rec.tool_call_id is not None and self._by_call_id.get(rec.tool_call_id) == oldest:
                del self._by_call_id[rec.tool_call_id]

    @staticmethod
    def _live(rec: ApprovalRecord, at: int) -> bool:
        return rec.confirmed_at is not None and rec.used_at is None and at <= rec.expires_at

    def issue(self, card: ApprovalCard) -> ApprovalRecord:
        at = self._now()
        rec = ApprovalRecord(
            id=card.id,
            tool_name=card.tool_name,
            tool_call_id=card.tool_call_id,
            canonical_args=card.canonical_args,
            digest=card.digest,
            created_at=at,
            expires_at=at + self._ttl,
        )
        self._records.pop(rec.id, None)
        self._records[rec.id] = rec
        if rec.tool_call_id is not None:
            self._by_call_id[rec.tool_call_id] = rec.id
        self._evict()
        return rec

    def confirm(self, id: str, digest: str, by: str | None = None) -> ApprovalRecord:
        rec = self._records.get(id)
        if rec is None:
            raise ApprovalMismatchError("unknown-id", id, f"no approval card {id}")
        if digest != rec.digest:
            raise ApprovalMismatchError("digest", id, f"approval {id}: digest does not match the card")
        at = self._now()
        if at > rec.expires_at:
            raise ApprovalMismatchError("expired", id, f"approval {id} expired")
        rec.confirmed_at = at
        if by is not None:
            rec.by = by
        return rec

    def lookup(self, call: ToolCall, canonical_args: str) -> ApprovalState | None:
        at = self._now()
        if call.tool_call_id is not None:
            known = self._by_call_id.get(call.tool_call_id)
            rec = None if known is None else self._records.get(known)
            if rec is not None and rec.confirmed_at is not None and rec.tool_name == call.tool_name:
                if rec.canonical_args != canonical_args:
                    return ApprovalState(rec.id, "mismatch")
                return ApprovalState(rec.id, "approved" if self._live(rec, at) else "expired")
        stale: ApprovalState | None = None
        for rec in reversed(list(self._records.values())):
            if rec.tool_name != call.tool_name or rec.confirmed_at is None or rec.canonical_args != canonical_args:
                continue
            if self._live(rec, at):
                return ApprovalState(rec.id, "approved")
            if stale is None:
                stale = ApprovalState(rec.id, "expired")
        return stale

    def consume(self, approval_id: str) -> None:
        rec = self._records.get(approval_id)
        if rec is not None:
            rec.used_at = self._now()


def create_approval_store(
    *, ttl_ms: int | None = None, max_pending: int | None = None, now: Callable[[], int] | None = None
) -> ApprovalStore:
    """Create a store. ``None`` takes the default, so a zero ``ttl_ms`` or ``max_pending`` is kept as zero."""
    return _Store(
        DEFAULT_APPROVAL_TTL_MS if ttl_ms is None else ttl_ms,
        DEFAULT_APPROVAL_MAX if max_pending is None else max_pending,
        _wall_ms if now is None else now,
    )


def _plain_str(value: str) -> str:
    """An exact ``str`` with the same characters, never running a subclass ``__str__`` or ``__format__`` (D32)."""
    return value if type(value) is str else str.__str__(value)


def _scalar_text(value: object) -> str:
    """JS ``String(value)`` for a scalar."""
    if isinstance(value, str):
        return _plain_str(value)
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        try:
            return js_number_str(float(value))
        except OverflowError:
            return _plain_str(str(value))
    return _plain_str(str(value))


# These types are scalars in JS or have no JS twin. Each keeps its str() text, never an attribute walk.
_SCALAR_TYPES = (
    str,
    int,
    float,
    complex,
    Decimal,
    Fraction,
    UUID,
    PurePath,
    timedelta,
    timezone,
    day_time,
    Enum,
    ModuleType,
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
    IPv4Interface,
    IPv6Interface,
)


_DICT_SLOTS = (GetSetDescriptorType, MemberDescriptorType)


def _slot_values(value: object) -> dict[str, Any] | None:
    """Set slot values, base class first, read through each member descriptor.

    Reads every class in the MRO, stdlib ones included. ``None`` unless a slot is set or a
    non-stdlib class declares ``__slots__``, even an empty one (e-b80c9f).
    """
    found: dict[str, Any] = {}
    declared = False
    for base in reversed(type(value).__mro__):
        raw = base.__dict__.get("__slots__")
        if raw is None:
            continue
        declared = declared or not _class_in_stdlib(base)
        for name in (raw,) if isinstance(raw, str) else tuple(raw):
            if name in ("__dict__", "__weakref__"):
                continue
            key = f"_{base.__name__.lstrip('_')}{name}" if name.startswith("__") and not name.endswith("__") else name
            slot = base.__dict__.get(key)
            if isinstance(slot, MemberDescriptorType):
                try:
                    found[key] = slot.__get__(value)
                except AttributeError:
                    pass
    return found if declared or found else None


def _dict_attributes(value: object) -> dict[Any, Any] | None:
    """Return the instance ``__dict__`` through the base descriptor, so no class code runs. ``None`` if it has none."""
    for base in type(value).__mro__:
        slot = base.__dict__.get("__dict__")
        if isinstance(slot, _DICT_SLOTS):
            try:
                found = slot.__get__(value)
            except (AttributeError, TypeError):
                return None
            return found if type(found) is dict else None
    return None


def _own_attributes(value: object) -> dict[Any, Any] | None:
    """Own attributes in JS order: set slots (base class first), then ``__dict__``. ``None`` if neither exists."""
    slots = _slot_values(value)
    attributes = _dict_attributes(value)
    if slots is None:
        return attributes
    return slots if attributes is None else {**slots, **attributes}


_CLASS_MODULE = type.__dict__["__module__"]
_WALKED_STDLIB_TYPES = (SimpleNamespace, Namespace, BaseException)


def _class_in_stdlib(cls: type) -> bool:
    """True when ``cls`` is defined in a stdlib module. Read off the class, so no class code runs."""
    module = _CLASS_MODULE.__get__(cls)
    return isinstance(module, str) and module.partition(".")[0] in sys.stdlib_module_names


def _from_stdlib(value: object) -> bool:
    """True when the class of ``value`` is defined in a stdlib module."""
    return _class_in_stdlib(type(value))


def _walks_like_a_js_object(value: object) -> bool:
    """Namespaces and any exception keep the attribute walk although their class is stdlib (PY-16b)."""
    return isinstance(value, _WALKED_STDLIB_TYPES)


def _members(value: object) -> Mapping[Any, Any] | None:
    """The key and value pairs JS ``Object.entries`` gives: a mapping's items, or a plain instance's attributes."""
    if isinstance(value, Mapping):
        return value
    if isinstance(value, _SCALAR_TYPES) or (_from_stdlib(value) and not _walks_like_a_js_object(value)):
        return None
    return _own_attributes(value)


def _scalar_leaves(args: Any, path: str, out: list[tuple[str, str]], depth: int = 0) -> None:
    if depth > _MAX_LEAF_DEPTH or callable(args) or isinstance(args, (set, frozenset, date)):
        return
    if isinstance(args, (bytes, bytearray)):
        for i, byte in enumerate(args):
            _scalar_leaves(byte, f"{path}.{i}", out, depth + 1)
    elif isinstance(args, (list, tuple)):
        for i, item in enumerate(args):
            _scalar_leaves(item, f"{path}[{i}]", out, depth + 1)
    elif (members := _members(args)) is not None:
        by_text: dict[str, list[Any]] = {}
        for raw_key, item in members.items():
            by_text.setdefault(_plain_str(raw_key if isinstance(raw_key, str) else str(raw_key)), []).append(item)
        for key in _js_key_order(list(by_text)):
            for item in by_text[key]:
                _scalar_leaves(item, f"{path}.{key}", out, depth + 1)
    else:
        out.append((path, _scalar_text(args)))


def _field_kind(path: str, value: str) -> ApprovalFieldKind:
    key = key_of(path)
    if key in DESTINATION_KEYS:
        return "destination"
    if key in _PAYLOAD_KEYS or utf16_len(value) > _PAYLOAD_UNITS:
        return "payload"
    return "other"


def _risk_of(decision: GuardDecision) -> Literal["low", "medium", "high"]:
    if decision.action == "block":
        return "high"
    if decision.requires_confirmation or decision.action == "flag":
        return "medium"
    return "low"


def render_approval_card(call: ToolCall, decision: GuardDecision) -> ApprovalRendered:
    """Return the human-readable card body. A field is tainted when a flow of ``decision`` landed on its path."""
    leaves: list[tuple[str, str]] = []
    _scalar_leaves(call.args, "args", leaves)
    fields: list[ApprovalField] = []
    for path, value in leaves:
        flow = next((f for f in decision.flows if f.path == path), None)
        shown = utf16_slice(value, 0, _MAX_FIELD_UNITS - 3) + "..." if utf16_len(value) > _MAX_FIELD_UNITS else value
        fields.append(
            ApprovalField(
                path=path,
                value=shown,
                tainted=flow is not None,
                source_tool=None if flow is None else flow.source_tool,
                kind=_field_kind(path, value),
            )
        )
    tainted = sum(1 for f in fields if f.tainted)
    tools = list(dict.fromkeys(f.source_tool for f in decision.flows))
    summary = (
        f"{decision.action}{' (needs approval)' if decision.requires_confirmation else ''}; "
        f"{tainted} tainted field{'' if tainted == 1 else 's'}" + (f" from {', '.join(tools)}" if tools else "")
    )
    return ApprovalRendered(
        title=f"{call.tool_name} → {decision.sink}",
        risk=_risk_of(decision),
        reasons=list(decision.reasons),
        summary=summary,
        fields=fields,
    )
