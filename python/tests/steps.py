"""Python port of datasets/steps.cjs: runs one agent-flows row against a guard (plan design item 5, D13, D19).

``run_row`` mirrors ``runRow`` op for op, with the same fake clock start. ``Recorder`` plays the part of
``recordingFactory`` in scripts/lib/py-export.cjs: it wraps every guard the row creates, ``fork()`` results
included, and keeps the approval cards and pinned locks in the fields the golden stores.
"""

import copy
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from prompt_protection.guard import ToolCall

CLOCK_START = 1_700_000_000_000
STEPS_CJS = Path(__file__).resolve().parents[2] / "datasets" / "steps.cjs"

OPS = frozenset(
    "trust taint memoryWrite memoryRead newGuard fork nextTurn approve advanceClock call pin lock redefineTool"
    " recordCost".split()
)


def js_ops() -> frozenset[str]:
    """The op names declared in ``const OPS = new Set([...])`` of datasets/steps.cjs."""
    block = re.search(r"const OPS = new Set\(\[(.*?)\]\);", STEPS_CJS.read_text(encoding="utf-8"), re.DOTALL)
    assert block is not None
    return frozenset(re.findall(r"'(\w+)'", re.sub(r"//[^\n]*", "", block.group(1))))


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _snake_keys(mapping: dict[str, Any]) -> dict[str, Any]:
    return {_snake(key): value for key, value in mapping.items()}


class Recorder:
    """Collects ``cards`` and ``locks`` from every guard it wraps, as the golden stores them."""

    def __init__(self) -> None:
        self.cards: list[dict[str, Any]] = []
        self.locks: list[dict[str, Any]] = []

    def wrap(self, guard: Any) -> "_RecordedGuard":
        return _RecordedGuard(guard, self)


class _RecordedGuard:
    def __init__(self, guard: Any, recorder: Recorder) -> None:
        self._guard = guard
        self._recorder = recorder

    def __getattr__(self, name: str) -> Any:
        return getattr(self._guard, name)

    def fork(self, **options: Any) -> "_RecordedGuard":
        return self._recorder.wrap(self._guard.fork(**options))

    def approval_card(self, call: ToolCall) -> Any:
        card = self._guard.approval_card(call)
        self._recorder.cards.append(
            {"toolName": card.tool_name, "digest": card.digest, "canonicalArgs": card.canonical_args}
        )
        return card

    def pin(self, tools: Any, **options: Any) -> Any:
        lock = self._guard.pin(tools, **options)
        self._recorder.locks.append({key: lock[key] for key in ("v", "algo", "rulesVersion", "tools")})
        return lock


def _call_of(spec: dict[str, Any]) -> ToolCall:
    return ToolCall(tool_name=spec["toolName"], args=spec["args"], tool_call_id=spec.get("toolCallId"))


def _drift_options(step: dict[str, Any]) -> dict[str, Any]:
    return {"drift": step["drift"]} if step.get("drift") is not None else {}


def run_row(create_guard: Callable[..., Any], row: dict[str, Any], recorder: Recorder | None = None) -> Any:
    """Run one dataset row and return the ``GuardDecision`` for ``row["call"]``."""
    now = CLOCK_START
    options = _snake_keys(row.get("options") or {})
    for name in ("budgets", "approvals"):
        if isinstance(options.get(name), dict):
            options[name] = _snake_keys(options[name])
    options["sinks"] = row.get("sinks") or {}
    options["approvals"] = {**options.get("approvals", {}), "now": lambda: now}

    def build() -> Any:
        guard = create_guard(**options)
        return guard if recorder is None else recorder.wrap(guard)

    guard = build()
    if row.get("user"):
        guard.analyze_user_turn(row["user"])
    for source in row.get("sources") or []:
        guard.taint(source["tool"], source["text"], id=source.get("id"))
    steps = row.get("steps")
    if not isinstance(steps, list):
        return guard.check_tool_call(_call_of(row["call"]))

    memory: dict[str, Any] = {}
    tools: dict[str, Any] = {}
    for step in steps:
        op = step["op"]
        if op not in OPS:
            raise ValueError(f"{row['id']}: unknown step op {op}")
        if op == "trust":
            guard.analyze_user_turn(step["text"])
        elif op == "taint":
            guard.taint(step["tool"], step["text"], id=step.get("id"))
        elif op == "memoryWrite":
            extra: dict[str, Any] = {}
            if step.get("key") is not None:
                extra["key"] = step["key"]
            if step.get("derivedFrom") is not None:
                extra["derived_from"] = step["derivedFrom"]
            policy = step.get("policy")
            written = guard.taint_memory_write(
                step["tool"], step["text"], id=step.get("id"), policy="annotate" if policy is None else policy, **extra
            )
            memory[step["id"]] = written.entry
        elif op == "memoryRead":
            entries = [memory.get(entry_id) for entry_id in step["ids"]]
            if any(entry is None for entry in entries):
                raise ValueError(f"{row['id']}: memoryRead of an unwritten id")
            guard.memory_read(entries)
        elif op == "newGuard":
            guard = build()
        elif op == "fork":
            guard = guard.fork()
        elif op == "nextTurn":
            guard.next_turn()
        elif op == "approve":
            card = guard.approval_card(_call_of(step))
            guard.confirm(card.id, card.digest, step.get("by"))
        elif op == "advanceClock":
            now += step["ms"]
        elif op == "pin":
            tools = copy.deepcopy(step["tools"])
            guard.pin(tools, **_drift_options(step))
        elif op == "lock":
            guard.lock(step["lock"], **_drift_options(step))
        elif op == "redefineTool":
            tools = {**tools, step["name"]: {**tools.get(step["name"], {}), **step["tool"]}}
            guard.wrap_tools(tools)
        elif op == "recordCost":
            guard.record_cost(**step["cost"])
        elif op == "call":
            guard.check_tool_call(_call_of(step))
    return guard.check_tool_call(_call_of(row["call"]))
