"""The default guard policies and their evaluation (twin of src/guard/policy.ts)."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from prompt_protection._result import JsResult
from prompt_protection.guard._types import FailMode, GuardPolicy, PolicyAction, PolicyContext
from prompt_protection.guard.sinks import EXEC_SINKS, EXFIL_SINKS

__all__ = [
    "DEFAULT_POLICIES",
    "PolicyOutcome",
    "approval_expired",
    "approval_mismatch",
    "args_injection",
    "budget_exceeded",
    "envelope_invalid",
    "evaluate_policies",
    "handoff_untrusted",
    "injection_source_flow",
    "injection_then_sink",
    "lineage_untrusted",
    "payment_confirm",
    "plan_violation",
    "tool_drift",
    "tool_unpinned",
    "turn_untrusted_to_untrusted_destination",
    "untrusted_to_exec",
    "untrusted_to_exfil_sink",
    "untrusted_to_payment",
]

_SEVERITY: dict[str, int] = {"allow": 0, "flag": 1, "confirm": 2, "block": 3}

_Verdict = Callable[[PolicyContext], PolicyAction | None]


@dataclass(frozen=True)
class _FunctionPolicy:
    id: str
    evaluate: _Verdict


def _policy(policy_id: str) -> Callable[[_Verdict], _FunctionPolicy]:
    def register(verdict: _Verdict) -> _FunctionPolicy:
        return _FunctionPolicy(policy_id, verdict)

    return register


def _flows_from_blocked_source(ctx: PolicyContext) -> bool:
    for flow in ctx.flows:
        source = ctx.source_by_id(flow.source_id)
        if source is not None and source.injection.action == "block":
            return True
    return False


def _exfil_risk(ctx: PolicyContext) -> bool:
    """Exfil sinks are safe when the user named every destination."""
    return ctx.sink in EXFIL_SINKS and not ctx.destination_trusted


def _exec_risk(ctx: PolicyContext) -> bool:
    """Exec runs anything tainted; file-write only cares about payloads and paths."""
    if ctx.sink == "exec":
        return len(ctx.flows) > 0
    if ctx.sink != "file-write":
        return False
    return any(f.kind != "identifier" or f.identifier_kind == "path" for f in ctx.flows)


def _flows_from_marker(ctx: PolicyContext, marker: str) -> bool:
    """A flow from a source whose lineage has an edge starting at the marker (``envelope:``, ``handoff:``)."""
    for flow in ctx.flows:
        source = ctx.source_by_id(flow.source_id)
        if source is not None and source.lineage is not None:
            if any(edge.from_.startswith(marker) for edge in source.lineage):
                return True
    return False


@_policy("plan-violation")
def plan_violation(ctx: PolicyContext) -> PolicyAction | None:
    return "block" if ctx.plan is not None and ctx.call.tool_name not in ctx.plan else None


@_policy("injection-source-flow")
def injection_source_flow(ctx: PolicyContext) -> PolicyAction | None:
    return "block" if (_exfil_risk(ctx) or _exec_risk(ctx)) and _flows_from_blocked_source(ctx) else None


@_policy("untrusted-to-exfil-sink")
def untrusted_to_exfil_sink(ctx: PolicyContext) -> PolicyAction | None:
    return "block" if _exfil_risk(ctx) and len(ctx.flows) > 0 else None


@_policy("untrusted-to-exec")
def untrusted_to_exec(ctx: PolicyContext) -> PolicyAction | None:
    return "block" if ctx.sink in EXEC_SINKS and _exec_risk(ctx) else None


@_policy("untrusted-to-payment")
def untrusted_to_payment(ctx: PolicyContext) -> PolicyAction | None:
    return "confirm" if ctx.sink == "payment" and len(ctx.flows) > 0 else None


@_policy("payment-confirm")
def payment_confirm(ctx: PolicyContext) -> PolicyAction | None:
    """Money moves only with a human in the loop, even when the user named the payee."""
    return "confirm" if ctx.sink == "payment" else None


@_policy("injection-then-sink")
def injection_then_sink(ctx: PolicyContext) -> PolicyAction | None:
    if ctx.sink != "none" and any(s.injection.action == "block" for s in ctx.turn_sources):
        return "flag"
    return None


@_policy("turn-untrusted-to-untrusted-destination")
def turn_untrusted_to_untrusted_destination(ctx: PolicyContext) -> PolicyAction | None:
    """Strict preset only: an unnamed exfil destination in a turn with untrusted sources and no detected flow."""
    if _exfil_risk(ctx) and len(ctx.flows) == 0 and len(ctx.turn_sources) > 0:
        return "confirm"
    return None


@_policy("args-injection")
def args_injection(ctx: PolicyContext) -> PolicyAction | None:
    return "flag" if ctx.sink != "none" and ctx.args_analysis.action != "allow" else None


@_policy("approval-mismatch")
def approval_mismatch(ctx: PolicyContext) -> PolicyAction | None:
    """A confirmed approval exists for this call id but the arguments changed since the card was shown."""
    return "block" if ctx.approval is not None and ctx.approval.status == "mismatch" else None


@_policy("approval-expired")
def approval_expired(ctx: PolicyContext) -> PolicyAction | None:
    """The matching approval expired or was already spent; ask again."""
    return "confirm" if ctx.approval is not None and ctx.approval.status == "expired" else None


@_policy("lineage-untrusted")
def lineage_untrusted(ctx: PolicyContext) -> PolicyAction | None:
    """A value whose lineage reaches a ``blocked`` source heads for exfil or exec."""
    if (_exfil_risk(ctx) or _exec_risk(ctx)) and any(ctx.label_of(f.source_id) == "blocked" for f in ctx.flows):
        return "block"
    return None


@_policy("tool-unpinned")
def tool_unpinned(ctx: PolicyContext) -> PolicyAction | None:
    """``require_lock`` without a lock, or a tool the lock does not list."""
    lock = ctx.lock
    return "block" if (ctx.require_lock and not lock.locked) or (lock.locked and not lock.listed) else None


@_policy("tool-drift")
def tool_drift(ctx: PolicyContext) -> PolicyAction | None:
    """A pinned tool whose definition changed since the lock; the lock's drift action picks block or confirm."""
    drift = ctx.lock.drift
    if drift is None or drift.kind == "missing":
        return None
    return "block" if ctx.lock.drift_action is None else ctx.lock.drift_action


@_policy("envelope-invalid")
def envelope_invalid(ctx: PolicyContext) -> PolicyAction | None:
    """A value from an envelope that failed verification is used at all."""
    return "block" if _flows_from_marker(ctx, "envelope:") else None


@_policy("handoff-untrusted")
def handoff_untrusted(ctx: PolicyContext) -> PolicyAction | None:
    """A value from a sealed handoff that failed verification is used at all."""
    return "block" if _flows_from_marker(ctx, "handoff:") else None


@_policy("budget-exceeded")
def budget_exceeded(ctx: PolicyContext) -> PolicyAction | None:
    """Any configured budget exceeded after counting this attempt."""
    return ctx.budget.on_exceed if ctx.budget is not None and len(ctx.budget.exceeded) > 0 else None


DEFAULT_POLICIES: tuple[GuardPolicy, ...] = (
    approval_mismatch,
    approval_expired,
    tool_unpinned,
    tool_drift,
    budget_exceeded,
    plan_violation,
    envelope_invalid,
    handoff_untrusted,
    injection_source_flow,
    lineage_untrusted,
    untrusted_to_exfil_sink,
    untrusted_to_exec,
    untrusted_to_payment,
    payment_confirm,
    injection_then_sink,
    args_injection,
)


@dataclass(frozen=True)
class PolicyOutcome(JsResult):
    """The verdict; ``reasons`` holds the ids of the policies that fired, most severe first."""

    action: PolicyAction
    reasons: list[str]
    policy: str | None = None


def evaluate_policies(
    policies: Sequence[GuardPolicy],
    ctx: PolicyContext,
    fail_mode: FailMode = "closed",
) -> PolicyOutcome:
    """Evaluate every policy; the most severe verdict wins and ties go to list order.

    A policy that raises blocks under ``fail_mode="closed"`` and is skipped under ``"open"``.
    """
    fired: list[tuple[str, PolicyAction]] = []
    for policy in policies:
        verdict: PolicyAction | None
        try:
            verdict = policy.evaluate(ctx)
        except Exception:
            if fail_mode == "open":
                continue
            verdict = "block"
        if verdict is not None and verdict != "allow":
            fired.append((policy.id, verdict))
    fired.sort(key=lambda item: -_SEVERITY[item[1]])
    if not fired:
        return PolicyOutcome("allow", [])
    return PolicyOutcome(fired[0][1], [policy_id for policy_id, _ in fired], fired[0][0])
