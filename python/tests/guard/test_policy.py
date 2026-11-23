"""RED tests for prompt_protection.guard.policy, .errors and the guard package exports.

Twins of src/guard/policy.ts and errors.ts (plan D1, D2, D32: expected values come from Node 22). No guard dataclass
is serialised here (D40).
"""

from types import SimpleNamespace
from typing import Any

import pytest

from prompt_protection import guard as guard_package
from prompt_protection.guard import errors, policy, reasons, sinks
from prompt_protection.guard._types import PolicyContext, ToolCall
from prompt_protection.guard.errors import ToolCallBlockedError
from prompt_protection.guard.policy import DEFAULT_POLICIES, evaluate_policies

# node -e "console.log(require('./dist/guard/index.cjs').DEFAULT_POLICIES.map((p) => p.id))"
JS_DEFAULT_POLICY_IDS = [
    "approval-mismatch",
    "approval-expired",
    "tool-unpinned",
    "tool-drift",
    "budget-exceeded",
    "plan-violation",
    "envelope-invalid",
    "handoff-untrusted",
    "injection-source-flow",
    "lineage-untrusted",
    "untrusted-to-exfil-sink",
    "untrusted-to-exec",
    "untrusted-to-payment",
    "payment-confirm",
    "injection-then-sink",
    "args-injection",
]

BLK = {"injection": "block"}
FLOW = [{"source_id": "s1"}]

# Each spec is built into a JS PolicyContext and evaluated by node with evaluatePolicies(DEFAULT_POLICIES, ctx).
# Columns: spec, action, reasons, policy, then each policy's own verdict (id -> action) for the firing policies.
CASES = [
    pytest.param({}, "allow", [], None, {}, id="clean-call-allows"),
    pytest.param(
        {"plan": ["read_file"], "tool_name": "write_file"},
        "block",
        ["plan-violation"],
        "plan-violation",
        {"plan-violation": "block"},
        id="plan-violation-tool-not-in-plan",
    ),
    pytest.param({"plan": ["tool"]}, "allow", [], None, {}, id="plan-allows-listed-tool"),
    pytest.param(
        {"plan": []},
        "block",
        ["plan-violation"],
        "plan-violation",
        {"plan-violation": "block"},
        id="plan-empty-allowlist-blocks-every-tool",
    ),
    pytest.param(
        {"approval": "mismatch"},
        "block",
        ["approval-mismatch"],
        "approval-mismatch",
        {"approval-mismatch": "block"},
        id="approval-mismatch",
    ),
    pytest.param(
        {"approval": "expired"},
        "confirm",
        ["approval-expired"],
        "approval-expired",
        {"approval-expired": "confirm"},
        id="approval-expired",
    ),
    pytest.param({"approval": "approved"}, "allow", [], None, {}, id="approval-approved-fires-nothing"),
    pytest.param(
        {"require_lock": True},
        "block",
        ["tool-unpinned"],
        "tool-unpinned",
        {"tool-unpinned": "block"},
        id="require-lock-without-lock",
    ),
    pytest.param(
        {"require_lock": True, "lock": {"locked": True, "listed": True}},
        "allow",
        [],
        None,
        {},
        id="require-lock-with-listed-tool",
    ),
    pytest.param(
        {"lock": {"locked": True, "listed": False}},
        "block",
        ["tool-unpinned"],
        "tool-unpinned",
        {"tool-unpinned": "block"},
        id="locked-tool-not-listed",
    ),
    pytest.param({"lock": {"locked": False, "listed": False}}, "allow", [], None, {}, id="unlocked-no-require-lock"),
    pytest.param(
        {"lock": {"locked": True, "listed": True, "drift_kind": "changed"}},
        "block",
        ["tool-drift"],
        "tool-drift",
        {"tool-drift": "block"},
        id="drift-changed-defaults-to-block",
    ),
    pytest.param(
        {"lock": {"locked": True, "listed": True, "drift_kind": "unlisted", "drift_action": "confirm"}},
        "confirm",
        ["tool-drift"],
        "tool-drift",
        {"tool-drift": "confirm"},
        id="drift-unlisted-confirm",
    ),
    pytest.param(
        {"lock": {"locked": True, "listed": True, "drift_kind": "missing"}},
        "allow",
        [],
        None,
        {},
        id="drift-missing-is-ignored",
    ),
    pytest.param(
        {"budget": {"exceeded": ["calls-per-turn"], "on_exceed": "block"}},
        "block",
        ["budget-exceeded"],
        "budget-exceeded",
        {"budget-exceeded": "block"},
        id="budget-exceeded-block",
    ),
    pytest.param(
        {"budget": {"exceeded": ["depth"], "on_exceed": "confirm"}},
        "confirm",
        ["budget-exceeded"],
        "budget-exceeded",
        {"budget-exceeded": "confirm"},
        id="budget-exceeded-confirm",
    ),
    pytest.param({"budget": {"exceeded": [], "on_exceed": "block"}}, "allow", [], None, {}, id="budget-within-limits"),
    pytest.param(
        {"flows": FLOW, "sources": {"s1": {"lineage": ["envelope:bad-signature"]}}},
        "block",
        ["envelope-invalid"],
        "envelope-invalid",
        {"envelope-invalid": "block"},
        id="envelope-marker-flow",
    ),
    pytest.param(
        {"flows": FLOW, "sources": {"s1": {"lineage": ["handoff:expired"]}}},
        "block",
        ["handoff-untrusted"],
        "handoff-untrusted",
        {"handoff-untrusted": "block"},
        id="handoff-marker-flow",
    ),
    pytest.param(
        {"flows": FLOW, "sources": {"s1": {"lineage": ["s0", "envelope:replayed"]}}},
        "block",
        ["envelope-invalid"],
        "envelope-invalid",
        {"envelope-invalid": "block"},
        id="marker-on-second-edge",
    ),
    pytest.param(
        {"flows": FLOW, "sources": {"s1": {"lineage": ["x-envelope:bad", "memory:handoff:k"]}}},
        "allow",
        [],
        None,
        {},
        id="marker-must-be-a-prefix",
    ),
    pytest.param(
        {"flows": FLOW, "sources": {"s1": {}, "s2": {"lineage": ["envelope:bad-signature"]}}},
        "allow",
        [],
        None,
        {},
        id="marker-source-not-in-flows",
    ),
    pytest.param({"flows": [{"source_id": "gone"}]}, "allow", [], None, {}, id="flow-from-unknown-source"),
    pytest.param({"flows": FLOW, "sources": {"s1": {}}}, "allow", [], None, {}, id="source-without-lineage"),
    pytest.param(
        {"sink": "network", "flows": FLOW, "sources": {"s1": BLK}},
        "block",
        ["injection-source-flow", "untrusted-to-exfil-sink"],
        "injection-source-flow",
        {"injection-source-flow": "block", "untrusted-to-exfil-sink": "block"},
        id="network-flow-from-blocked-source",
    ),
    pytest.param(
        {"sink": "network", "flows": FLOW, "sources": {"s1": BLK}, "destination_trusted": True},
        "allow",
        [],
        None,
        {},
        id="network-flow-trusted-destination",
    ),
    pytest.param(
        {"sink": "network", "flows": FLOW, "sources": {"s1": {}}},
        "block",
        ["untrusted-to-exfil-sink"],
        "untrusted-to-exfil-sink",
        {"untrusted-to-exfil-sink": "block"},
        id="network-flow-from-clean-source",
    ),
    pytest.param({"sink": "network"}, "allow", [], None, {}, id="network-without-flows"),
    pytest.param(
        {"sink": "email", "flows": FLOW, "sources": {"s1": {}}},
        "block",
        ["untrusted-to-exfil-sink"],
        "untrusted-to-exfil-sink",
        {"untrusted-to-exfil-sink": "block"},
        id="email-flow",
    ),
    pytest.param(
        {"sink": "message", "flows": FLOW, "sources": {"s1": {}}},
        "block",
        ["untrusted-to-exfil-sink"],
        "untrusted-to-exfil-sink",
        {"untrusted-to-exfil-sink": "block"},
        id="message-flow",
    ),
    pytest.param(
        {"sink": "unknown", "flows": FLOW, "sources": {"s1": {}}},
        "block",
        ["untrusted-to-exfil-sink"],
        "untrusted-to-exfil-sink",
        {"untrusted-to-exfil-sink": "block"},
        id="unknown-sink-flow",
    ),
    pytest.param(
        {"sink": "unknown", "flows": FLOW, "sources": {"s1": {}}, "destination_trusted": True},
        "allow",
        [],
        None,
        {},
        id="unknown-sink-flow-trusted-destination",
    ),
    pytest.param({"sink": "none", "flows": FLOW, "sources": {"s1": BLK}}, "allow", [], None, {}, id="none-sink-flow"),
    pytest.param(
        {"sink": "exec", "flows": FLOW, "sources": {"s1": {}}},
        "block",
        ["untrusted-to-exec"],
        "untrusted-to-exec",
        {"untrusted-to-exec": "block"},
        id="exec-flow",
    ),
    pytest.param(
        {"sink": "exec", "flows": FLOW, "sources": {"s1": {}}, "destination_trusted": True},
        "block",
        ["untrusted-to-exec"],
        "untrusted-to-exec",
        {"untrusted-to-exec": "block"},
        id="exec-flow-trusted-destination",
    ),
    pytest.param(
        {"sink": "exec", "flows": FLOW, "sources": {"s1": BLK}},
        "block",
        ["injection-source-flow", "untrusted-to-exec"],
        "injection-source-flow",
        {"injection-source-flow": "block", "untrusted-to-exec": "block"},
        id="exec-flow-from-blocked-source",
    ),
    pytest.param({"sink": "exec"}, "allow", [], None, {}, id="exec-without-flows"),
    pytest.param(
        {"sink": "file-write", "flows": [{"source_id": "s1", "kind": "content"}], "sources": {"s1": {}}},
        "block",
        ["untrusted-to-exec"],
        "untrusted-to-exec",
        {"untrusted-to-exec": "block"},
        id="file-write-content-flow",
    ),
    pytest.param(
        {"sink": "file-write", "flows": FLOW, "sources": {"s1": {}}},
        "block",
        ["untrusted-to-exec"],
        "untrusted-to-exec",
        {"untrusted-to-exec": "block"},
        id="file-write-exact-flow",
    ),
    pytest.param(
        {
            "sink": "file-write",
            "flows": [{"source_id": "s1", "kind": "identifier", "identifier_kind": "path"}],
            "sources": {"s1": {}},
        },
        "block",
        ["untrusted-to-exec"],
        "untrusted-to-exec",
        {"untrusted-to-exec": "block"},
        id="file-write-path-identifier-flow",
    ),
    pytest.param(
        {
            "sink": "file-write",
            "flows": [{"source_id": "s1", "kind": "identifier", "identifier_kind": "email"}],
            "sources": {"s1": {}},
        },
        "allow",
        [],
        None,
        {},
        id="file-write-email-identifier-flow",
    ),
    pytest.param(
        {"sink": "file-write", "flows": [{"source_id": "s1", "kind": "identifier"}], "sources": {"s1": {}}},
        "allow",
        [],
        None,
        {},
        id="file-write-identifier-flow-without-kind",
    ),
    pytest.param(
        {"sink": "network", "flows": FLOW, "sources": {"s1": {"label": "blocked"}}},
        "block",
        ["lineage-untrusted", "untrusted-to-exfil-sink"],
        "lineage-untrusted",
        {"lineage-untrusted": "block", "untrusted-to-exfil-sink": "block"},
        id="lineage-blocked-label-to-network",
    ),
    pytest.param(
        {"sink": "exec", "flows": FLOW, "sources": {"s1": {"label": "blocked"}}},
        "block",
        ["lineage-untrusted", "untrusted-to-exec"],
        "lineage-untrusted",
        {"lineage-untrusted": "block", "untrusted-to-exec": "block"},
        id="lineage-blocked-label-to-exec",
    ),
    pytest.param(
        {"sink": "none", "flows": FLOW, "sources": {"s1": {"label": "blocked"}}},
        "allow",
        [],
        None,
        {},
        id="lineage-blocked-label-to-none-sink",
    ),
    pytest.param(
        {"sink": "network", "flows": FLOW, "sources": {"s1": {"label": "memory"}}},
        "block",
        ["untrusted-to-exfil-sink"],
        "untrusted-to-exfil-sink",
        {"untrusted-to-exfil-sink": "block"},
        id="lineage-memory-label-to-network",
    ),
    pytest.param(
        {"sink": "payment", "flows": FLOW, "sources": {"s1": {}}},
        "confirm",
        ["untrusted-to-payment", "payment-confirm"],
        "untrusted-to-payment",
        {"untrusted-to-payment": "confirm", "payment-confirm": "confirm"},
        id="payment-with-flow",
    ),
    pytest.param(
        {"sink": "payment"},
        "confirm",
        ["payment-confirm"],
        "payment-confirm",
        {"payment-confirm": "confirm"},
        id="payment-without-flow",
    ),
    pytest.param(
        {"sink": "payment", "destination_trusted": True},
        "confirm",
        ["payment-confirm"],
        "payment-confirm",
        {"payment-confirm": "confirm"},
        id="payment-trusted-destination",
    ),
    pytest.param(
        {"sink": "network", "turn_sources": ["block"], "destination_trusted": True},
        "flag",
        ["injection-then-sink"],
        "injection-then-sink",
        {"injection-then-sink": "flag"},
        id="injection-in-turn-then-network-sink",
    ),
    pytest.param(
        {"sink": "none", "turn_sources": ["block"]}, "allow", [], None, {}, id="injection-in-turn-then-none-sink"
    ),
    pytest.param(
        {"sink": "exec", "turn_sources": ["flag", "allow"]},
        "allow",
        [],
        None,
        {},
        id="flagged-turn-source-is-not-injection",
    ),
    pytest.param(
        {"sink": "exec", "args_action": "flag"},
        "flag",
        ["args-injection"],
        "args-injection",
        {"args-injection": "flag"},
        id="args-flag-on-exec",
    ),
    pytest.param(
        {"sink": "email", "args_action": "block", "destination_trusted": True},
        "flag",
        ["args-injection"],
        "args-injection",
        {"args-injection": "flag"},
        id="args-block-on-email",
    ),
    pytest.param({"sink": "none", "args_action": "flag"}, "allow", [], None, {}, id="args-flag-on-none-sink"),
    pytest.param({"sink": "exec", "args_action": "allow"}, "allow", [], None, {}, id="args-allow-on-exec"),
    pytest.param(
        {"sink": "payment", "flows": FLOW, "sources": {"s1": {}}, "approval": "mismatch"},
        "block",
        ["approval-mismatch", "untrusted-to-payment", "payment-confirm"],
        "approval-mismatch",
        {"approval-mismatch": "block", "untrusted-to-payment": "confirm", "payment-confirm": "confirm"},
        id="block-outranks-confirm",
    ),
    pytest.param(
        {"sink": "payment", "args_action": "flag", "turn_sources": ["block"]},
        "confirm",
        ["payment-confirm", "injection-then-sink", "args-injection"],
        "payment-confirm",
        {"payment-confirm": "confirm", "injection-then-sink": "flag", "args-injection": "flag"},
        id="confirm-outranks-flag",
    ),
    pytest.param(
        {"sink": "exec", "flows": FLOW, "sources": {"s1": BLK}, "plan": ["other"], "approval": "mismatch"},
        "block",
        ["approval-mismatch", "plan-violation", "injection-source-flow", "untrusted-to-exec"],
        "approval-mismatch",
        {
            "approval-mismatch": "block",
            "plan-violation": "block",
            "injection-source-flow": "block",
            "untrusted-to-exec": "block",
        },
        id="equal-severity-keeps-list-order",
    ),
    pytest.param(
        {
            "sink": "payment",
            "flows": FLOW,
            "sources": {"s1": {"injection": "block", "label": "blocked", "lineage": ["envelope:x"]}},
            "turn_sources": ["block"],
            "args_action": "flag",
            "approval": "expired",
            "require_lock": True,
            "budget": {"exceeded": ["depth"], "on_exceed": "confirm"},
        },
        "block",
        [
            "tool-unpinned",
            "envelope-invalid",
            "approval-expired",
            "budget-exceeded",
            "untrusted-to-payment",
            "payment-confirm",
            "injection-then-sink",
            "args-injection",
        ],
        "tool-unpinned",
        {
            "approval-expired": "confirm",
            "tool-unpinned": "block",
            "budget-exceeded": "confirm",
            "envelope-invalid": "block",
            "untrusted-to-payment": "confirm",
            "payment-confirm": "confirm",
            "injection-then-sink": "flag",
            "args-injection": "flag",
        },
        id="every-severity-at-once",
    ),
]

# node: evaluatePolicies(policies, ctx[, failMode]) over policies that return the listed verdict or throw.
CUSTOM_CASES = [
    pytest.param([], (), "allow", [], None, id="no-policies"),
    pytest.param([("a", None), ("b", "allow")], (), "allow", [], None, id="all-pass"),
    pytest.param([("a", "flag")], (), "flag", ["a"], "a", id="single-flag"),
    pytest.param(
        [("a", "flag"), ("b", "block"), ("c", "confirm"), ("d", "flag")],
        (),
        "block",
        ["b", "c", "a", "d"],
        "b",
        id="severity-orders-reasons",
    ),
    pytest.param(
        [("a", "confirm"), ("b", "confirm"), ("c", "block"), ("d", "block")],
        (),
        "block",
        ["c", "d", "a", "b"],
        "c",
        id="ties-keep-list-order",
    ),
    pytest.param([("a", "allow"), ("b", "flag")], (), "flag", ["b"], "b", id="allow-verdict-is-not-a-reason"),
    pytest.param([("a", None), ("boom", "throw")], (), "block", ["boom"], "boom", id="throw-closed-default"),
    pytest.param(
        [("boom", "throw"), ("a", "flag")], ("closed",), "block", ["boom", "a"], "boom", id="throw-closed-explicit"
    ),
    pytest.param([("boom", "throw"), ("a", "flag")], ("open",), "flag", ["a"], "a", id="throw-open-skips"),
    pytest.param([("boom", "throw")], ("open",), "allow", [], None, id="throw-open-alone"),
    pytest.param(
        [("a", "flag"), ("boom", "throw"), ("b", "block")],
        ("closed",),
        "block",
        ["boom", "b", "a"],
        "boom",
        id="throw-closed-ranks-with-block",
    ),
]

# node -e: new ToolCallBlockedError(decision).message for each decision shape below.
ERROR_CASES = [
    pytest.param(
        ("http_post", "untrusted-to-exfil-sink", "network", 2),
        'prompt-protection: tool call "http_post" blocked by untrusted-to-exfil-sink (sink network, 2 flow(s))',
        id="policy-named",
    ),
    pytest.param(
        ("run_shell", None, "exec", 0),
        'prompt-protection: tool call "run_shell" blocked by guard (sink exec, 0 flow(s))',
        id="no-policy-reads-guard",
    ),
    pytest.param(
        ("t", "", "none", 1),
        'prompt-protection: tool call "t" blocked by  (sink none, 1 flow(s))',
        id="empty-policy-is-kept",
    ),
    pytest.param(
        ("pay", "payment-confirm", "payment", 3),
        'prompt-protection: tool call "pay" blocked by payment-confirm (sink payment, 3 flow(s))',
        id="payment",
    ),
]

REEXPORTS = [
    pytest.param(reasons, "DECISION_REASONS"),
    pytest.param(reasons, "is_decision_reason"),
    pytest.param(sinks, "default_sink"),
    pytest.param(sinks, "create_sink_resolver"),
    pytest.param(sinks, "EXFIL_SINKS"),
    pytest.param(sinks, "EXEC_SINKS"),
    pytest.param(policy, "DEFAULT_POLICIES"),
    pytest.param(policy, "evaluate_policies"),
    pytest.param(errors, "ToolCallBlockedError"),
]


def make_source(source_id: str, spec: dict[str, Any]) -> SimpleNamespace:
    lineage = [SimpleNamespace(from_=origin) for origin in spec["lineage"]] if "lineage" in spec else None
    return SimpleNamespace(
        id=source_id,
        injection=SimpleNamespace(action=spec.get("injection", "allow")),
        label=spec.get("label"),
        lineage=lineage,
    )


def make_lock(spec: dict[str, Any]) -> SimpleNamespace:
    drift_kind = spec.get("drift_kind")
    return SimpleNamespace(
        locked=spec["locked"],
        listed=spec["listed"],
        drift=None if drift_kind is None else SimpleNamespace(kind=drift_kind),
        drift_action=spec.get("drift_action"),
        annotations=None,
    )


def make_context(spec: dict[str, Any]) -> PolicyContext:
    sources = {source_id: make_source(source_id, d) for source_id, d in spec.get("sources", {}).items()}
    budget = spec.get("budget")
    plan = spec.get("plan")
    approval = spec.get("approval")
    return PolicyContext(
        call=ToolCall(tool_name=spec.get("tool_name", "tool"), args={}),
        sink=spec.get("sink", "none"),
        flows=[
            SimpleNamespace(
                kind=f.get("kind", "exact"), source_id=f["source_id"], identifier_kind=f.get("identifier_kind")
            )
            for f in spec.get("flows", [])
        ],
        sources=list(sources.values()),
        turn_sources=[SimpleNamespace(injection=SimpleNamespace(action=a)) for a in spec.get("turn_sources", [])],
        args_analysis=SimpleNamespace(action=spec.get("args_action", "allow")),
        plan=None if plan is None else frozenset(plan),
        destination_trusted=spec.get("destination_trusted", False),
        source_by_id=sources.get,
        label_of=lambda source_id: getattr(sources.get(source_id), "label", None) or "tool",
        depth=0,
        approval=None if approval is None else SimpleNamespace(status=approval),
        lock=make_lock(spec.get("lock", {"locked": False, "listed": True})),
        budget=None if budget is None else SimpleNamespace(exceeded=budget["exceeded"], on_exceed=budget["on_exceed"]),
        require_lock=spec.get("require_lock", False),
    )


def make_policy(policy_id: str, verdict: str | None) -> SimpleNamespace:
    def evaluate(ctx: object) -> str | None:
        if verdict == "throw":
            raise RuntimeError("policy failed")
        return verdict

    return SimpleNamespace(id=policy_id, evaluate=evaluate)


def firing_verdicts(ctx: PolicyContext) -> dict[str, str]:
    verdicts = {p.id: p.evaluate(ctx) for p in DEFAULT_POLICIES}
    return {policy_id: verdict for policy_id, verdict in verdicts.items() if verdict not in (None, "allow")}


def outcome_tuple(outcome: Any) -> tuple[str, list[str], str | None]:
    return outcome.action, list(outcome.reasons), outcome.policy


def make_decision(tool_name: str, policy_id: str | None, sink: str, flow_count: int) -> SimpleNamespace:
    return SimpleNamespace(tool_name=tool_name, policy=policy_id, sink=sink, flows=[object()] * flow_count)


def test_default_policies_are_the_js_policies_in_order() -> None:
    assert [p.id for p in DEFAULT_POLICIES] == JS_DEFAULT_POLICY_IDS


@pytest.mark.parametrize(("spec", "action", "reasons", "policy_id", "verdicts"), CASES)
def test_evaluate_policies_over_default_policies_matches_node(
    spec: dict[str, Any], action: str, reasons: list[str], policy_id: str | None, verdicts: dict[str, str]
) -> None:
    outcome = evaluate_policies(DEFAULT_POLICIES, make_context(spec))
    assert outcome_tuple(outcome) == (action, reasons, policy_id)


@pytest.mark.parametrize(("spec", "action", "reasons", "policy_id", "verdicts"), CASES)
def test_each_default_policy_verdict_matches_node(
    spec: dict[str, Any], action: str, reasons: list[str], policy_id: str | None, verdicts: dict[str, str]
) -> None:
    assert firing_verdicts(make_context(spec)) == verdicts


@pytest.mark.parametrize("policy_id", JS_DEFAULT_POLICY_IDS)
def test_each_default_policy_fires_in_some_cases_and_stays_quiet_in_others(policy_id: str) -> None:
    target = next(p for p in DEFAULT_POLICIES if p.id == policy_id)
    verdicts = [target.evaluate(make_context(case.values[0])) for case in CASES]
    fired = [v for v in verdicts if v not in (None, "allow")]
    assert 0 < len(fired) < len(verdicts)


@pytest.mark.parametrize(("policies", "extra", "action", "reasons", "policy_id"), CUSTOM_CASES)
def test_evaluate_policies_orders_reasons_and_handles_a_throwing_policy_like_node(
    policies: list[tuple[str, str | None]],
    extra: tuple[str, ...],
    action: str,
    reasons: list[str],
    policy_id: str | None,
) -> None:
    outcome = evaluate_policies([make_policy(*p) for p in policies], make_context({}), *extra)
    assert outcome_tuple(outcome) == (action, reasons, policy_id)


def test_evaluate_policies_runs_every_policy_even_after_a_block() -> None:
    calls: list[str] = []

    def recording(policy_id: str, verdict: str | None) -> SimpleNamespace:
        return SimpleNamespace(id=policy_id, evaluate=lambda ctx: calls.append(policy_id) or verdict)

    evaluate_policies([recording("p1", "block"), recording("p2", None)], make_context({}))
    assert calls == ["p1", "p2"]


def test_evaluate_policies_hands_each_policy_the_same_context() -> None:
    seen: list[object] = []
    ctx = make_context({})
    spy = SimpleNamespace(id="spy", evaluate=lambda c: seen.append(c))
    evaluate_policies([spy, spy], ctx)
    assert len(seen) == 2
    assert all(c is ctx for c in seen)


@pytest.mark.parametrize(("shape", "message"), ERROR_CASES)
def test_tool_call_blocked_error_message_matches_node(shape: tuple[str, str | None, str, int], message: str) -> None:
    assert str(ToolCallBlockedError(make_decision(*shape))) == message


def test_tool_call_blocked_error_is_an_exception_carrying_its_decision() -> None:
    decision = make_decision("http_post", "untrusted-to-exfil-sink", "network", 2)
    with pytest.raises(ToolCallBlockedError) as info:
        raise ToolCallBlockedError(decision)
    assert isinstance(info.value, Exception)
    assert info.value.decision is decision
    assert type(info.value).__name__ == "ToolCallBlockedError"


@pytest.mark.parametrize(("module", "name"), REEXPORTS)
def test_guard_package_reexports_the_same_object(module: Any, name: str) -> None:
    assert getattr(guard_package, name) is getattr(module, name)
