"""Plain-language explanation of a guard decision (twin of src/guard/explain.ts, plan D2, D40, e-0dc5fc).

``flows`` are the plain camelCase dicts of ``logging_.FlowSummary``, as in a log event.
"""

from collections.abc import Callable
from dataclasses import dataclass

from prompt_protection.guard._types import GuardDecision
from prompt_protection.logging_ import FlowSummary, _summarize_flows

__all__ = ["ExplainStep", "Explanation", "explain"]


@dataclass(frozen=True)
class ExplainStep:
    """One reason code. ``policy`` is the policy id the code names, ``None`` for ``approved``."""

    code: str
    policy: str | None
    because: str
    flows: list[FlowSummary]


@dataclass(frozen=True)
class Explanation:
    summary: str
    chain: list[ExplainStep]


def _unpinned(d: GuardDecision) -> str:
    if d.lock is not None and d.lock.locked:
        return f"{d.tool_name} is not in the tool lock"
    return "require_lock is set and no lock is installed"


def _drift(d: GuardDecision) -> str:
    kind = d.lock.drift.kind if d.lock is not None and d.lock.drift is not None else "changed"
    return f"the pinned definition of {d.tool_name} changed ({kind})"


def _budget(d: GuardDecision) -> str:
    exceeded = ", ".join(d.budget.exceeded) if d.budget is not None else ""
    return f"budget exceeded: {exceeded or 'a configured limit'}"


def _fixed(text: str) -> Callable[[GuardDecision], str]:
    return lambda _d: text


_BECAUSE: dict[str, Callable[[GuardDecision], str]] = {
    "plan-violation": lambda d: f"{d.tool_name} is not in the plan() allow-list for this turn",
    "injection-source-flow": lambda d: f"a source that itself scored as injection flows into {d.tool_name}",
    "untrusted-to-exfil-sink": lambda d: (
        f"untrusted data reaches an exfil sink ({d.sink}) and the user did not name every destination"
    ),
    "untrusted-to-exec": lambda d: f"untrusted data reaches an execution sink ({d.sink})",
    "untrusted-to-payment": _fixed("untrusted data reaches a payment sink; a human must confirm"),
    "payment-confirm": _fixed("money moves only with a human in the loop"),
    "injection-then-sink": _fixed(
        "a source this turn scored as injection and the call targets a sink, even without a detected flow"
    ),
    "args-injection": _fixed("the tool-call arguments themselves read as injection"),
    "approval-mismatch": _fixed(
        "a confirmed approval exists for this call id but the arguments changed since the card was shown"
    ),
    "approval-expired": _fixed("the matching approval expired or was already spent; ask again"),
    "approved": _fixed("a human approved these exact arguments; the confirm was cleared once"),
    "lineage-untrusted": _fixed(
        "a value whose lineage reaches a blocked source (memory, handoff, derivation) heads for exfil or exec"
    ),
    "handoff-untrusted": _fixed("the parent handoff could not be verified, so its sources are treated as blocked"),
    "tool-unpinned": _unpinned,
    "tool-drift": _drift,
    "budget-exceeded": _budget,
    "envelope-invalid": _fixed("a sealed envelope failed verification, so its payload is treated as blocked"),
    "internal-error": _fixed("the guard itself threw; the verdict comes from fail_mode"),
}


def _summary(d: GuardDecision) -> str:
    verdict = "confirm" if d.requires_confirmation else d.action
    sink = "no sink" if d.sink == "none" else f"sink {d.sink}"
    lock = ", locked" if d.lock is not None and d.lock.locked else ""
    observed = ""
    if d.observed_action is not None:
        would_be = "confirm" if d.observed_requires_confirmation else d.observed_action
        observed = f" (observe mode; enforced verdict would be {would_be})"
    top = f": {d.reasons[0]}" if d.reasons else ""
    return f"{verdict} {d.tool_name} ({sink}{lock}, depth {d.depth}){top}{observed}"


def explain(decision: GuardDecision) -> Explanation:
    """Return one step per reason code in decision order. A code with no entry gets a generic line."""
    flows = _summarize_flows(decision.flows)
    chain: list[ExplainStep] = []
    for code in decision.reasons:
        line = _BECAUSE.get(code)
        because = f'policy or check "{code}" fired' if line is None else line(decision)
        is_policy = code != "approved"
        chain.append(ExplainStep(code, code if is_policy else None, because, list(flows) if is_policy else []))
    return Explanation(_summary(decision), chain)
