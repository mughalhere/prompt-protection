"""The pure tool-call decision function (twin of src/guard/check.ts, plan D1, D2, D40).

State is passed in through ``CheckContext``, so ``create_guard`` stays thin. Each call emits one event
through ``emit_tool_call_log``. Approvals and observe mode belong to later tasks.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, cast

from prompt_protection._rules import _FLAGS, Rule
from prompt_protection.analyze import (
    DEFAULT_THRESHOLD,
    AnalysisResult,
    analyze_prompt,
    compute_severity,
    failed_analysis,
)
from prompt_protection.guard._types import (
    FailMode,
    GuardDecision,
    GuardPolicy,
    PolicyAction,
    PolicyContext,
    SinkKind,
    TaintedSource,
    ToolCall,
)
from prompt_protection.guard.budgets import Budget, BudgetState
from prompt_protection.guard.pin import UNLOCKED, LockView
from prompt_protection.guard.policy import evaluate_policies
from prompt_protection.guard.provenance import (
    Flow,
    FlowThresholds,
    SourceIndex,
    TrustState,
    collect_leaves,
    detect_flows,
)
from prompt_protection.logging_ import LoggingOptions, emit_tool_call_log
from prompt_protection.scorer import PatternMatch
from prompt_protection.verdict import Action

__all__ = ["CheckContext", "check_tool_call"]

FLOW_RULE = Rule(
    id="guard-data-flow",
    source="(?!)",
    weight=10,
    category="data-flow",
    precision="high",
    pattern=re.compile("(?!)", _FLAGS),
    description="Untrusted tool-result data reached a tool-call argument",
)


@dataclass(frozen=True, kw_only=True)
class CheckContext:
    """The guard state one decision reads. ``label_of`` answers the provenance label of a source id."""

    index: SourceIndex
    trust: TrustState
    thresholds: FlowThresholds
    policies: Sequence[GuardPolicy]
    resolve_sink: Callable[[str], SinkKind]
    plan: frozenset[str] | None
    turn: int
    analyze_options: Mapping[str, Any]
    fail_mode: FailMode
    label_of: Callable[[str], str]
    depth: int
    logging: LoggingOptions
    lock_of: Callable[[str], LockView] | None = None
    require_lock: bool = False
    budget: Budget | None = None


def _threshold(ctx: CheckContext) -> float:
    value = ctx.analyze_options.get("threshold")
    return DEFAULT_THRESHOLD if value is None else float(value)


def _failed_decision(err: Exception, call: ToolCall, ctx: CheckContext) -> GuardDecision:
    """Block unless ``fail_mode`` is ``open``; the sink is ``none`` when the resolver is what threw."""
    args_analysis = failed_analysis(err, ctx.fail_mode, _threshold(ctx))
    sink: SinkKind = "none"
    try:
        sink = ctx.resolve_sink(call.tool_name)
    except Exception:
        pass
    decision = GuardDecision(
        action=args_analysis.action,
        requires_confirmation=False,
        tool_name=call.tool_name,
        tool_call_id=call.tool_call_id,
        sink=sink,
        flows=[],
        reasons=["internal-error"],
        policy="internal-error",
        args_analysis=args_analysis,
        depth=ctx.depth,
    )
    emit_tool_call_log(decision, "", ctx.logging)
    return decision


def check_tool_call(call: ToolCall, ctx: CheckContext) -> GuardDecision:
    """Decide one tool call. An internal failure becomes the ``internal-error`` decision.

    If the logger raises and ``on_logger_error`` raises too, the call becomes the ``internal-error``
    decision, and the exception escapes when that decision is logged too. A callback that raises for an
    awaitable result is swallowed and never changes the decision.
    """
    try:
        return _run_check(call, ctx)
    except Exception as err:
        return _failed_decision(err, call, ctx)


def _snapshot(state: BudgetState) -> BudgetState:
    """Copy the counts a decision keeps. ``cost`` stays shared with the live state, as in JS."""
    return replace(state, tool_calls=dict(state.tool_calls), repeats=dict(state.repeats), exceeded=list(state.exceeded))


def _to_action(action: PolicyAction) -> Action:
    return "flag" if action == "confirm" else action


def _with_flow_matches(result: AnalysisResult, flows: list[Flow], action: Action, threshold: float) -> AnalysisResult:
    if not flows and action == result.action:
        return result
    synthetic = [PatternMatch(replace(FLOW_RULE, id=f"guard-data-flow-{f.kind}"), f.value, 0, 0) for f in flows]
    categories = list(dict.fromkeys([*result.categories, "data-flow"])) if flows else result.categories
    score = max(result.score, threshold) if action == "block" else result.score
    return replace(
        result,
        score=score,
        severity=compute_severity(score),
        action=action,
        is_malicious=action == "block",
        matches=[*result.matches, *synthetic],
        categories=categories,
    )


def _empty_analysis() -> AnalysisResult:
    return AnalysisResult(0, "safe", False, "allow", [], [], "")


def _run_check(call: ToolCall, ctx: CheckContext) -> GuardDecision:
    leaves = collect_leaves(call.args)
    sink = ctx.resolve_sink(call.tool_name)
    report = detect_flows(leaves, ctx.index, ctx.trust, ctx.thresholds)
    args_text = "\n".join(leaf.value for leaf in report.untrusted_leaves)
    raw_args = analyze_prompt(args_text, **ctx.analyze_options) if args_text else _empty_analysis()

    lock = UNLOCKED if ctx.lock_of is None else ctx.lock_of(call.tool_name)
    budget = None if ctx.budget is None else ctx.budget.record(call, ctx.depth)
    sources = cast(Sequence[TaintedSource], ctx.index.sources)
    outcome = evaluate_policies(
        ctx.policies,
        PolicyContext(
            call=call,
            sink=sink,
            flows=report.flows,
            sources=sources,
            turn_sources=[s for s in sources if s.turn == ctx.turn],
            args_analysis=raw_args,
            plan=ctx.plan,
            destination_trusted=report.destination_trusted,
            source_by_id=cast(Callable[[str], TaintedSource | None], ctx.index.get),
            label_of=ctx.label_of,
            depth=ctx.depth,
            approval=None,
            lock=lock,
            budget=budget,
            require_lock=ctx.require_lock,
        ),
        ctx.fail_mode,
    )
    enforced = _to_action(outcome.action)
    decision = GuardDecision(
        action=enforced,
        requires_confirmation=outcome.action == "confirm",
        tool_name=call.tool_name,
        tool_call_id=call.tool_call_id,
        sink=sink,
        flows=report.flows,
        reasons=list(outcome.reasons),
        policy=outcome.policy if outcome.action != "allow" else None,
        args_analysis=_with_flow_matches(raw_args, report.flows, enforced, _threshold(ctx)),
        depth=ctx.depth,
        lock=lock if lock.locked else None,
        budget=None if budget is None else _snapshot(budget),
    )
    emit_tool_call_log(decision, args_text, ctx.logging)
    return decision
