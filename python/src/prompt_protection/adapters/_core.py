"""Helpers shared by the framework ``protect()`` adapters (twin of src/adapters/protect-core.ts).

This module imports no framework package, so it loads with the extras not installed.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from prompt_protection._types import FailMode
from prompt_protection.guard import GuardDecision

__all__ = ["Denial", "denial", "error_message", "guarded"]

_T = TypeVar("_T")


@dataclass(frozen=True)
class Denial:
    code: str
    message: str


def denial(decision: GuardDecision) -> Denial:
    """The one-line reason a framework surfaces when the guard refuses a call."""
    if decision.policy is not None:
        code = decision.policy
    else:
        code = decision.reasons[0] if decision.reasons else "blocked"
    flows = ""
    if decision.flows:
        paths = dict.fromkeys(f"{flow.path} from {flow.source_tool}" for flow in decision.flows)
        flows = f"; tainted: {', '.join(paths)}"
    verdict = "needs approval" if decision.requires_confirmation else "denied"
    return Denial(code, f"prompt-protection: {decision.tool_name} {verdict} ({code}; sink {decision.sink}{flows})")


def guarded(
    fn: Callable[[], _T],
    fail_mode: FailMode,
    closed: Callable[[Exception], _T],
    open_: Callable[[Exception], _T],
) -> _T:
    """Run a hook under the fail mode: an ``Exception`` yields ``closed(err)`` (deny) or ``open_(err)`` (pass)."""
    try:
        return fn()
    except Exception as err:
        return open_(err) if fail_mode == "open" else closed(err)


def error_message(err: BaseException) -> str:
    return str(err)
