"""Direct tests for nine built-in guard policies (twins of the policy objects in src/guard/policy.ts).

Covered: plan_violation, injection_source_flow, untrusted_to_exfil_sink, untrusted_to_exec, untrusted_to_payment,
payment_confirm, injection_then_sink, lineage_untrusted and tool_drift. Expected actions, ids, the order of
DEFAULT_POLICIES and the combined outcomes were taken from Node 22 by calling ``evaluate`` on the built package
(dist/guard/index.cjs) with the same contexts.
"""

from types import SimpleNamespace
from typing import Any

import pytest

from prompt_protection import guard as guard_package
from prompt_protection.guard.policy import (
    DEFAULT_POLICIES,
    evaluate_policies,
    injection_source_flow,
    injection_then_sink,
    lineage_untrusted,
    payment_confirm,
    plan_violation,
    tool_drift,
    untrusted_to_exec,
    untrusted_to_exfil_sink,
    untrusted_to_payment,
)

SINKS = ("none", "network", "email", "message", "unknown", "exec", "file-write", "payment")
BLOCKED_SOURCE = {"s1": {"injection": "block"}}
CLEAN_SOURCE = {"s1": {"injection": "allow"}}
DEFAULT_LOCK = {"locked": True, "listed": True, "drift": None, "drift_action": None}


def flow(source_id: str = "s1", kind: str = "text", identifier_kind: str | None = None) -> dict[str, Any]:
    return {"source_id": source_id, "kind": kind, "identifier_kind": identifier_kind}


TEXT = [flow()]


def make_context(
    sink: str = "none",
    flows: list[dict[str, Any]] | None = None,
    sources: dict[str, dict[str, Any]] | None = None,
    turn_sources: list[str] | None = None,
    destination_trusted: bool = False,
    plan: list[str] | None = None,
    tool: str = "t",
    lock: dict[str, Any] | None = None,
) -> Any:
    """A PolicyContext stand-in built from plain data; ``sources`` maps an id to injection, label and lineage."""
    known = sources or {}
    lock_spec = {**DEFAULT_LOCK, **(lock or {})}
    drift = None if lock_spec["drift"] is None else SimpleNamespace(kind=lock_spec["drift"])
    return SimpleNamespace(
        call=SimpleNamespace(tool_name=tool),
        sink=sink,
        flows=[SimpleNamespace(**spec) for spec in flows or []],
        turn_sources=[SimpleNamespace(injection=SimpleNamespace(action=action)) for action in turn_sources or []],
        destination_trusted=destination_trusted,
        plan=None if plan is None else frozenset(plan),
        source_by_id=lambda sid: (
            SimpleNamespace(injection=SimpleNamespace(action=known[sid]["injection"])) if sid in known else None
        ),
        label_of=lambda sid: known.get(sid, {}).get("label", "untrusted"),
        lock=SimpleNamespace(
            locked=lock_spec["locked"], listed=lock_spec["listed"], drift=drift, drift_action=lock_spec["drift_action"]
        ),
    )


def cases(policy: Any, rows: list[tuple[str, str | None, dict[str, Any]]]) -> list[Any]:
    return [pytest.param(policy, spec, expected, id=f"{policy.id}:{name}") for name, expected, spec in rows]


def by_sink(name: str, expected: dict[str, str], **spec: Any) -> list[tuple[str, str | None, dict[str, Any]]]:
    """One row per sink; a sink missing from ``expected`` means the policy returns ``None``."""
    return [(f"{name}:{sink}", expected.get(sink), {**spec, "sink": sink}) for sink in SINKS]


def sinks_with(action: str, *sinks: str) -> dict[str, str]:
    return dict.fromkeys(sinks, action)


EXFIL = ("network", "email", "message", "unknown")
EXFIL_AND_EXEC = (*EXFIL, "exec", "file-write")
PATH_FLOW = [flow(kind="identifier", identifier_kind="path")]
URL_FLOW = [flow(kind="identifier", identifier_kind="url")]
UNKIND_FLOW = [flow(kind="identifier")]
LABELLED_BLOCKED = {"s1": {"injection": "allow", "label": "blocked"}}

POLICY_CASES = [
    *cases(
        plan_violation,
        [
            ("no-plan", None, {}),
            ("tool-in-plan", None, {"plan": ["t"]}),
            ("tool-among-others", None, {"plan": ["a", "t"]}),
            ("tool-not-in-plan", "block", {"plan": ["a", "b"]}),
            ("empty-plan-blocks-everything", "block", {"plan": []}),
            ("plan-match-is-case-sensitive", "block", {"plan": ["T"]}),
            ("sink-and-flows-do-not-matter", "block", {"plan": ["a"], "sink": "payment", "flows": TEXT}),
            ("sink-and-flows-do-not-matter-when-listed", None, {"plan": ["t"], "sink": "payment", "flows": TEXT}),
        ],
    ),
    *cases(
        injection_source_flow,
        [
            *by_sink("blocked-flow", sinks_with("block", *EXFIL_AND_EXEC), flows=TEXT, sources=BLOCKED_SOURCE),
            *by_sink(
                "blocked-flow-to-trusted-destination",
                sinks_with("block", "exec", "file-write"),
                flows=TEXT,
                sources=BLOCKED_SOURCE,
                destination_trusted=True,
            ),
            ("no-flows", None, {"sink": "network", "sources": BLOCKED_SOURCE}),
            ("clean-source", None, {"sink": "network", "flows": TEXT, "sources": CLEAN_SOURCE}),
            ("flag-is-not-block", None, {"sink": "network", "flows": TEXT, "sources": {"s1": {"injection": "flag"}}}),
            ("unknown-source", None, {"sink": "network", "flows": TEXT}),
            (
                "second-flow-is-blocked",
                "block",
                {
                    "sink": "network",
                    "flows": [flow("s1"), flow("s2")],
                    "sources": {"s1": {"injection": "allow"}, "s2": {"injection": "block"}},
                },
            ),
            (
                "file-write-path-identifier",
                "block",
                {"sink": "file-write", "flows": PATH_FLOW, "sources": BLOCKED_SOURCE},
            ),
            ("file-write-url-identifier", None, {"sink": "file-write", "flows": URL_FLOW, "sources": BLOCKED_SOURCE}),
            ("exec-without-flows", None, {"sink": "exec", "sources": BLOCKED_SOURCE}),
        ],
    ),
    *cases(
        untrusted_to_exfil_sink,
        [
            *by_sink("flow", sinks_with("block", *EXFIL), flows=TEXT),
            *by_sink("flow-to-trusted-destination", {}, flows=TEXT, destination_trusted=True),
            ("no-flows", None, {"sink": "network"}),
            ("identifier-flow", "block", {"sink": "network", "flows": URL_FLOW}),
            ("flow-from-unknown-source", "block", {"sink": "email", "flows": TEXT, "sources": {}}),
            ("two-flows", "block", {"sink": "message", "flows": [flow("s1"), flow("s2")]}),
        ],
    ),
    *cases(
        untrusted_to_exec,
        [
            *by_sink("flow", sinks_with("block", "exec", "file-write"), flows=TEXT),
            ("exec-without-flows", None, {"sink": "exec"}),
            ("exec-identifier-flow", "block", {"sink": "exec", "flows": URL_FLOW}),
            ("exec-trusted-destination", "block", {"sink": "exec", "flows": TEXT, "destination_trusted": True}),
            ("file-write-without-flows", None, {"sink": "file-write"}),
            ("file-write-path-identifier", "block", {"sink": "file-write", "flows": PATH_FLOW}),
            ("file-write-url-identifier", None, {"sink": "file-write", "flows": URL_FLOW}),
            ("file-write-identifier-without-kind", None, {"sink": "file-write", "flows": UNKIND_FLOW}),
            ("file-write-identifier-then-text", "block", {"sink": "file-write", "flows": [*URL_FLOW, *TEXT]}),
        ],
    ),
    *cases(
        untrusted_to_payment,
        [
            *by_sink("flow", sinks_with("confirm", "payment"), flows=TEXT),
            ("payment-without-flows", None, {"sink": "payment"}),
            ("payment-trusted-destination", "confirm", {"sink": "payment", "flows": TEXT, "destination_trusted": True}),
            ("payment-identifier-flow", "confirm", {"sink": "payment", "flows": URL_FLOW}),
        ],
    ),
    *cases(
        payment_confirm,
        [
            *by_sink("no-flows", sinks_with("confirm", "payment")),
            ("payment-with-flows", "confirm", {"sink": "payment", "flows": TEXT}),
            ("payment-trusted-destination", "confirm", {"sink": "payment", "destination_trusted": True}),
            ("other-sink-with-flows", None, {"sink": "network", "flows": TEXT}),
        ],
    ),
    *cases(
        injection_then_sink,
        [
            *by_sink("blocked-turn-source", sinks_with("flag", *SINKS[1:]), turn_sources=["block"]),
            ("custom-sink", "flag", {"sink": "custom", "turn_sources": ["block"]}),
            ("no-turn-sources", None, {"sink": "network"}),
            ("turn-sources-without-a-block", None, {"sink": "network", "turn_sources": ["allow", "flag"]}),
            ("one-blocked-among-others", "flag", {"sink": "network", "turn_sources": ["allow", "block"]}),
            ("flows-do-not-matter", "flag", {"sink": "exec", "turn_sources": ["block"], "flows": TEXT}),
        ],
    ),
    *cases(
        lineage_untrusted,
        [
            *by_sink("blocked-label", sinks_with("block", *EXFIL_AND_EXEC), flows=TEXT, sources=LABELLED_BLOCKED),
            *by_sink(
                "blocked-label-to-trusted-destination",
                sinks_with("block", "exec", "file-write"),
                flows=TEXT,
                sources=LABELLED_BLOCKED,
                destination_trusted=True,
            ),
            ("no-flows", None, {"sink": "network", "sources": LABELLED_BLOCKED}),
            ("untrusted-label", None, {"sink": "network", "flows": TEXT, "sources": {"s1": {"label": "untrusted"}}}),
            (
                "label-is-case-sensitive",
                None,
                {"sink": "network", "flows": TEXT, "sources": {"s1": {"label": "Blocked"}}},
            ),
            (
                "injection-score-is-not-the-label",
                None,
                {"sink": "network", "flows": TEXT, "sources": {"s1": {"injection": "block", "label": "untrusted"}}},
            ),
            ("flow-from-unknown-source", None, {"sink": "network", "flows": TEXT}),
            (
                "second-flow-is-blocked",
                "block",
                {
                    "sink": "network",
                    "flows": [flow("s1"), flow("s2")],
                    "sources": {"s1": {"label": "untrusted"}, "s2": {"label": "blocked"}},
                },
            ),
            (
                "file-write-path-identifier",
                "block",
                {"sink": "file-write", "flows": PATH_FLOW, "sources": LABELLED_BLOCKED},
            ),
            ("file-write-url-identifier", None, {"sink": "file-write", "flows": URL_FLOW, "sources": LABELLED_BLOCKED}),
        ],
    ),
    *cases(
        tool_drift,
        [
            ("no-drift", None, {}),
            *[
                (f"{kind}-drift:{configured}", expected, {"lock": {"drift": kind, "drift_action": configured}})
                for kind in ("changed", "unlisted")
                for configured, expected in ((None, "block"), ("block", "block"), ("confirm", "confirm"))
            ],
            *[
                (f"missing-drift:{configured}", None, {"lock": {"drift": "missing", "drift_action": configured}})
                for configured in (None, "block", "confirm")
            ],
            ("lock-flags-are-not-read", "block", {"lock": {"locked": False, "listed": False, "drift": "changed"}}),
        ],
    ),
]


@pytest.mark.parametrize(("policy", "spec", "expected"), POLICY_CASES)
def test_policy_returns_the_action_for_a_context(policy: Any, spec: dict[str, Any], expected: str | None) -> None:
    assert policy.evaluate(make_context(**spec)) == expected


REGISTRATIONS = [
    pytest.param("plan_violation", plan_violation, "plan-violation", 5, id="plan_violation"),
    pytest.param(
        "injection_source_flow", injection_source_flow, "injection-source-flow", 8, id="injection_source_flow"
    ),
    pytest.param("lineage_untrusted", lineage_untrusted, "lineage-untrusted", 9, id="lineage_untrusted"),
    pytest.param(
        "untrusted_to_exfil_sink", untrusted_to_exfil_sink, "untrusted-to-exfil-sink", 10, id="untrusted_to_exfil_sink"
    ),
    pytest.param("untrusted_to_exec", untrusted_to_exec, "untrusted-to-exec", 11, id="untrusted_to_exec"),
    pytest.param("untrusted_to_payment", untrusted_to_payment, "untrusted-to-payment", 12, id="untrusted_to_payment"),
    pytest.param("payment_confirm", payment_confirm, "payment-confirm", 13, id="payment_confirm"),
    pytest.param("injection_then_sink", injection_then_sink, "injection-then-sink", 14, id="injection_then_sink"),
    pytest.param("tool_drift", tool_drift, "tool-drift", 3, id="tool_drift"),
]


@pytest.mark.parametrize(("name", "policy", "policy_id", "position"), REGISTRATIONS)
def test_policy_id_export_and_position_in_default_policies(
    name: str, policy: Any, policy_id: str, position: int
) -> None:
    assert policy.id == policy_id
    assert getattr(guard_package, name) is policy
    assert name in guard_package.__all__
    assert DEFAULT_POLICIES[position] is policy


def test_default_policies_hold_each_policy_once() -> None:
    assert all(DEFAULT_POLICIES.count(param.values[1]) == 1 for param in REGISTRATIONS)


EXPLOITING_FLOW = {
    "sink": "network",
    "flows": TEXT,
    "sources": {"s1": {"injection": "block", "label": "blocked"}},
    "turn_sources": ["block"],
}
OUTCOMES = [
    pytest.param(
        EXPLOITING_FLOW,
        (
            "block",
            ["injection-source-flow", "lineage-untrusted", "untrusted-to-exfil-sink", "injection-then-sink"],
            "injection-source-flow",
        ),
        id="exfil-of-a-blocked-source",
    ),
    pytest.param(
        {"sink": "payment", "flows": TEXT, "sources": CLEAN_SOURCE, "turn_sources": ["block"]},
        ("confirm", ["untrusted-to-payment", "payment-confirm", "injection-then-sink"], "untrusted-to-payment"),
        id="payment-of-a-flow",
    ),
    pytest.param(
        {"sink": "exec", "flows": TEXT, "sources": CLEAN_SOURCE, "plan": ["other"]},
        ("block", ["plan-violation", "untrusted-to-exec"], "plan-violation"),
        id="exec-outside-the-plan",
    ),
    pytest.param(
        {
            "sink": "payment",
            "flows": TEXT,
            "sources": CLEAN_SOURCE,
            "lock": {"drift": "changed", "drift_action": "confirm"},
        },
        ("confirm", ["tool-drift", "untrusted-to-payment", "payment-confirm"], "tool-drift"),
        id="drift-listed-before-payment",
    ),
    pytest.param({"sink": "none"}, ("allow", [], None), id="nothing-fires"),
]
NINE = [policy for policy in DEFAULT_POLICIES if policy in {param.values[1] for param in REGISTRATIONS}]


@pytest.mark.parametrize(("spec", "expected"), OUTCOMES)
def test_the_nine_policies_together_decide_by_severity_then_list_order(
    spec: dict[str, Any], expected: tuple[str, list[str], str | None]
) -> None:
    outcome = evaluate_policies(NINE, make_context(**spec))
    assert (outcome.action, outcome.reasons, outcome.policy) == expected


def test_every_policy_in_the_matrix_is_registered() -> None:
    assert len(NINE) == 9
    assert {policy.id for policy in NINE} == {param.values[2] for param in REGISTRATIONS}
