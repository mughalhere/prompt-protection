"""Wrap tools so each ``execute`` is checked, run and tainted (twin of src/guard/wrap.ts)."""

import inspect
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from prompt_protection.guard._types import GuardDecision, ToolCall
from prompt_protection.guard.errors import ToolCallBlockedError

__all__ = ["WrapHooks", "wrap_tools"]


@dataclass(frozen=True)
class WrapHooks:
    """The two guard operations ``wrap_tools`` needs: decide a call, and taint a result."""

    check: Callable[[ToolCall], GuardDecision]
    taint: Callable[[str, object, str], object]


def _call_id_of(options: Mapping[str, object]) -> str | None:
    call_id = options.get("tool_call_id")
    return call_id if isinstance(call_id, str) else None


def _wrap_one(name: str, execute: Callable[..., Any], hooks: WrapHooks) -> Callable[..., Any]:
    def wrapped(input: Any, **options: Any) -> Any:
        call_id = _call_id_of(options)
        decision = hooks.check(ToolCall(tool_name=name, args=input, tool_call_id=call_id))
        if decision.action == "block":
            raise ToolCallBlockedError(decision)
        result = execute(input, **options)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise TypeError(f'prompt-protection: tool "{name}" returned an awaitable, wrap_tools is sync-only')
        source_id = call_id if call_id is not None else f"{name}:{time.time_ns() // 1_000_000}:{secrets.token_hex(3)}"
        hooks.taint(name, result, source_id)
        return result

    return wrapped


def wrap_tools(tools: Mapping[str, Mapping[str, Any]], hooks: WrapHooks) -> dict[str, Mapping[str, Any]]:
    """Return a new dict where every tool with a callable ``execute`` checks, runs, then taints.

    A tool without a callable ``execute`` is returned as it came. ``execute`` is called as
    ``execute(input, **options)`` and the ``tool_call_id`` option names the call.
    """
    out: dict[str, Mapping[str, Any]] = {}
    for name, tool in tools.items():
        execute = tool.get("execute")
        out[name] = {**tool, "execute": _wrap_one(name, execute, hooks)} if callable(execute) else tool
    return out
