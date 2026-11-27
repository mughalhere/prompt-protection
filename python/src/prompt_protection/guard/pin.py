"""Tool pinning (twin of src/guard/pin.ts).

A ``ToolLock`` is a wire dict with the JS keys. Pin and verify are sync and hash with sha256.
``ToolDrift``, ``LockView`` and ``LockState`` are frozen dataclasses read by attribute.
"""

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar, Literal, TypedDict, TypeGuard

from prompt_protection._result import JsResult
from prompt_protection._rules import RULES_VERSION
from prompt_protection.canonical import canonical_json, digest

__all__ = [
    "UNLOCKED",
    "DriftAction",
    "LockState",
    "LockView",
    "PinnedTool",
    "ToolAnnotations",
    "ToolDrift",
    "ToolIdentity",
    "ToolLike",
    "ToolLock",
    "ToolSet",
    "identity_text",
    "is_tool_lock",
    "pin_tools",
    "tool_identities",
    "tool_identity",
    "verify_tools",
]

DriftAction = Literal["block", "confirm"]
ToolAnnotations = dict[str, Any]
ToolLike = Mapping[str, Any]
ToolSet = Mapping[str, ToolLike] | Sequence[ToolLike]


class ToolIdentity(TypedDict):
    name: str
    description: str
    schema: object
    annotations: ToolAnnotations | None


class _PinnedToolRequired(TypedDict):
    digest: str


class PinnedTool(_PinnedToolRequired, total=False):
    annotations: ToolAnnotations


class ToolLock(TypedDict):
    v: int
    algo: str
    createdAt: str
    rulesVersion: str
    tools: dict[str, PinnedTool]


@dataclass(frozen=True, kw_only=True)
class ToolDrift(JsResult):
    """``changed``: definition differs. ``unlisted``: not in the lock. ``missing``: pinned, absent now."""

    name: str
    kind: Literal["changed", "unlisted", "missing"]
    expected: str | None = None
    actual: str | None = None


@dataclass(frozen=True, kw_only=True)
class LockView(JsResult):
    """Lock state as the check pipeline sees it for one tool name. ``listed`` is always true when unlocked."""

    locked: bool
    listed: bool
    drift: ToolDrift | None
    annotations: ToolAnnotations | None
    drift_action: DriftAction | None = None
    _js_nullable: ClassVar[frozenset[str]] = frozenset({"drift", "annotations"})


@dataclass(frozen=True, kw_only=True)
class LockState(JsResult):
    lock: ToolLock | None
    drift: list[ToolDrift]
    drift_action: DriftAction
    _js_nullable: ClassVar[frozenset[str]] = frozenset({"lock"})


UNLOCKED = LockView(locked=False, listed=True, drift=None, annotations=None)


def tool_identity(name: str, tool: ToolLike) -> ToolIdentity:
    """What a pinned tool is: name, description, schema and annotations. Never ``execute``."""
    description = tool.get("description")
    schema = tool.get("inputSchema")
    if schema is None:
        schema = tool.get("parameters")
    return {
        "name": name,
        "description": "" if description is None else description,
        "schema": schema,
        "annotations": tool.get("annotations"),
    }


def tool_identities(tools: ToolSet) -> dict[str, ToolIdentity]:
    """Name to identity. A sequence names each tool by its own ``name``, a mapping by its key."""
    out: dict[str, ToolIdentity] = {}
    if isinstance(tools, Mapping):
        for name, tool in tools.items():
            out[name] = tool_identity(name, tool)
        return out
    for tool in tools:
        own_name = tool.get("name")
        if isinstance(own_name, str) and own_name:
            out[own_name] = tool_identity(own_name, tool)
    return out


def identity_text(identity: ToolIdentity) -> str:
    """Canonical text of an identity. Equal text means equal digest, so a sync compare can use it."""
    return canonical_json(identity)


def _created_at() -> str:
    ms = time.time_ns() // 1_000_000
    stamp = datetime.fromtimestamp(ms // 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{stamp}.{ms % 1000:03d}Z"


def pin_tools(tools: ToolSet) -> ToolLock:
    """Digest every tool definition (never ``execute``) into a v1 ``sha256`` lock."""
    entries: dict[str, PinnedTool] = {}
    for name, identity in tool_identities(tools).items():
        pinned: PinnedTool = {"digest": digest(identity_text(identity))}
        if identity["annotations"] is not None:
            pinned["annotations"] = identity["annotations"]
        entries[name] = pinned
    return {"v": 1, "algo": "sha256", "createdAt": _created_at(), "rulesVersion": RULES_VERSION, "tools": entries}


def verify_tools(tools: ToolSet, lock: ToolLock) -> list[ToolDrift]:
    """Drift between current definitions and a lock. An empty list means byte-identical identities."""
    drift: list[ToolDrift] = []
    current = tool_identities(tools)
    for name, identity in current.items():
        pinned = lock["tools"].get(name)
        actual = digest(identity_text(identity))
        if pinned is None:
            drift.append(ToolDrift(name=name, kind="unlisted", actual=actual))
        elif pinned["digest"] != actual:
            drift.append(ToolDrift(name=name, kind="changed", expected=pinned["digest"], actual=actual))
    for name, pinned in lock["tools"].items():
        if name not in current:
            drift.append(ToolDrift(name=name, kind="missing", expected=pinned.get("digest")))
    return drift


def is_tool_lock(value: object) -> TypeGuard[ToolLock]:
    """True for a structurally valid v1 lock. JSON ``true`` is not the version 1."""
    if not isinstance(value, Mapping):
        return False
    version = value.get("v")
    if isinstance(version, bool) or not isinstance(version, (int, float)) or version != 1:
        return False
    if value.get("algo") not in ("sha256", "fnv1a64"):
        return False
    tools = value.get("tools")
    if not isinstance(value.get("createdAt"), str) or not isinstance(value.get("rulesVersion"), str):
        return False
    if not isinstance(tools, Mapping):
        return False
    return all(isinstance(t, Mapping) and isinstance(t.get("digest"), str) for t in tools.values())
