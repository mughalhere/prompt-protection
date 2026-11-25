"""RED tests for three owner rulings on budgets (PY-18, rulings Q1, Q2 and Q4).

Q2 and Q4 expected values come from Node 22 running dist/guard/index.cjs. Q1 pins a divergence from JS.
"""

from typing import Any

import pytest

from prompt_protection.guard import ToolCall, create_budget, create_guard

LIVE_PARAMS = ("usd", "tokens")


def _circular() -> dict[str, Any]:
    args: dict[str, Any] = {}
    args["self"] = args
    return args


def _nested(levels: int) -> dict[str, Any]:
    args: dict[str, Any] = {}
    for _ in range(levels):
        args = {"x": args}
    return args


def tools_guard(names: list[str], per_each: int, **options: Any) -> Any:
    guard = create_guard(budgets=options)
    for name in names:
        for _ in range(per_each):
            guard.check_tool_call(ToolCall(tool_name=name, args={}))
    return guard


# owner ruling Q1, bead 6it: a decision's budget cost is its own copy; JS shares it with the live state.
@pytest.mark.parametrize("field", LIVE_PARAMS)
def test_a_decisions_budget_cost_does_not_change_when_cost_is_recorded_later_owner_ruled_divergence_from_js(
    field: str,
) -> None:
    guard = create_guard(budgets={})
    decision = guard.check_tool_call(ToolCall(tool_name="get_weather", args={}))
    guard.record_cost(**{field: 3})
    assert (decision.budget.cost.usd, decision.budget.cost.tokens) == (0, 0)
    assert getattr(guard.budget().cost, field) == 3
    assert decision.budget.cost is not guard.budget().cost


# owner ruling Q2: canonical_json runs before the budget counts, as in JS.
@pytest.mark.parametrize(
    "args",
    [
        pytest.param(_circular(), id="circular"),
        pytest.param({"x": float("nan")}, id="nan"),
        pytest.param(_nested(70), id="nested-deeper-than-64"),
        pytest.param({"x": {1}}, id="set"),
    ],
)
def test_args_that_canonical_json_rejects_give_internal_error_and_leave_the_budget_untouched(
    args: Any,
) -> None:
    guard = create_guard(budgets={})
    decision = guard.check_tool_call(ToolCall(tool_name="t", args=args))
    assert (decision.action, decision.policy, decision.reasons) == ("block", "internal-error", ["internal-error"])
    assert decision.budget is None
    state = guard.budget()
    assert (state.turn_calls, dict(state.tool_calls), dict(state.repeats)) == (0, {}, {})
    assert guard.check_tool_call(ToolCall(tool_name="t", args={})).budget.turn_calls == 1


# owner ruling Q4: integer-like names list ascending first, then the rest in insertion order (Node 22).
INTEGER_NAME_ORDER = ["10", "2", "a", "1"]
MIXED_NAME_ORDER = ["10", "2", "a", "1", "b", "-1", "01", "1.5", "4294967294", "4294967295"]
KINDS_NAME_ORDER = ["b", "10", "a", "2", "1"]
KINDS_OPTIONS: dict[str, Any] = {
    "max_calls_per_turn": 1,
    "max_calls_per_tool": {"b": 1, "10": 1, "a": 1, "2": 1, "1": 1},
    "max_depth": -1,
    "max_cost": {"usd": -1},
    "max_repeat_identical": 1,
}
KINDS_EXCEEDED = [
    "calls-per-turn",
    "calls-per-tool:1",
    "calls-per-tool:2",
    "calls-per-tool:10",
    "calls-per-tool:b",
    "calls-per-tool:a",
    "repeat-identical",
    "depth",
    "cost:usd",
]
ORDER_CASES = [
    pytest.param(
        INTEGER_NAME_ORDER,
        2,
        {"max_calls_per_tool": 1, "max_repeat_identical": 100},
        ["calls-per-tool:1", "calls-per-tool:2", "calls-per-tool:10", "calls-per-tool:a"],
        id="integers-and-a-letter",
    ),
    pytest.param(
        MIXED_NAME_ORDER,
        2,
        {"max_calls_per_tool": 1, "max_repeat_identical": 100},
        [
            "calls-per-tool:1",
            "calls-per-tool:2",
            "calls-per-tool:10",
            "calls-per-tool:4294967294",
            "calls-per-tool:a",
            "calls-per-tool:b",
            "calls-per-tool:-1",
            "calls-per-tool:01",
            "calls-per-tool:1.5",
            "calls-per-tool:4294967295",
        ],
        id="array-index-boundary-and-non-integer-names",
    ),
    pytest.param(KINDS_NAME_ORDER, 4, KINDS_OPTIONS, KINDS_EXCEEDED, id="other-exceeded-kinds-keep-their-place"),
]


@pytest.mark.parametrize(("names", "per_each", "options", "expected"), ORDER_CASES)
def test_the_exceeded_list_orders_integer_like_tool_names_the_js_way(
    names: list[str], per_each: int, options: dict[str, Any], expected: list[str]
) -> None:
    assert list(tools_guard(names, per_each, **options).budget().exceeded) == expected


# owner ruling Q3: an on_exceed outside block and confirm fails closed; only an absent or None value means block.
def _exceeded_decision(**on_exceed: Any) -> Any:
    guard = create_guard(budgets={"max_calls_per_turn": 0, **on_exceed})
    return guard.check_tool_call(ToolCall(tool_name="t", args={}))


@pytest.mark.parametrize("value", ["", "warn"], ids=["empty-string", "warn"])
def test_an_on_exceed_outside_block_and_confirm_gives_internal_error_owner_ruled_divergence_from_js(value: str) -> None:
    decision = _exceeded_decision(on_exceed=value)
    assert (decision.action, decision.policy, decision.reasons) == ("block", "internal-error", ["internal-error"])


@pytest.mark.parametrize("options", [{}, {"on_exceed": None}], ids=["absent", "none"])
def test_an_absent_or_none_on_exceed_means_block(options: dict[str, Any]) -> None:
    decision = _exceeded_decision(**options)
    assert (decision.action, decision.policy, decision.reasons) == ("block", "budget-exceeded", ["budget-exceeded"])
    assert decision.budget.on_exceed == "block"


# owner ruling Q6: the tool_calls mapping iterates in JS object key order. Expected orders measured on Node 22.
Q6_NAMES = MIXED_NAME_ORDER
Q6_JS_KEYS = ["1", "2", "10", "4294967294", "a", "b", "-1", "01", "1.5", "4294967295"]


def _call(name: str) -> ToolCall:
    return ToolCall(tool_name=name, args={})


def _guard_budget(names: list[str]) -> Any:
    guard = create_guard(budgets={})
    for name in names:
        guard.check_tool_call(_call(name))
    return guard.budget()


def _decision_budget(names: list[str]) -> Any:
    guard = create_guard(budgets={})
    decision = None
    for name in names:
        decision = guard.check_tool_call(_call(name))
    return decision.budget


def _budget_record_return(names: list[str]) -> Any:
    budget = create_budget()
    state = None
    for name in names:
        state = budget.record(_call(name), 0)
    return state


def _budget_state(names: list[str]) -> Any:
    budget = create_budget()
    for name in names:
        budget.record(_call(name), 0)
    return budget.state


Q6_SURFACES = [
    pytest.param(_guard_budget, id="guard-budget"),
    pytest.param(_decision_budget, id="decision-budget-snapshot"),
    pytest.param(_budget_record_return, id="create-budget-record-return"),
    pytest.param(_budget_state, id="create-budget-state"),
]


@pytest.mark.parametrize("surface", Q6_SURFACES)
def test_tool_calls_keys_iterate_in_js_object_key_order_owner_ruling_q6(surface: Any) -> None:
    assert list(surface(Q6_NAMES).tool_calls) == Q6_JS_KEYS


@pytest.mark.parametrize("surface", Q6_SURFACES)
def test_tool_calls_items_keep_their_counts_in_js_order_owner_ruling_q6(surface: Any) -> None:
    state = surface(["10", "a", "10", "2", "a", "a"])
    assert list(state.tool_calls.items()) == [("2", 1), ("10", 2), ("a", 3)]


def test_an_earlier_decision_snapshot_keeps_its_own_js_order_while_the_live_state_grows_owner_ruling_q6() -> None:
    guard = create_guard(budgets={})
    for name in ["10", "2", "a"]:
        guard.check_tool_call(_call(name))
    middle = guard.check_tool_call(_call("1"))
    guard.check_tool_call(_call("0"))
    assert list(middle.budget.tool_calls) == ["1", "2", "10", "a"]
    assert list(guard.budget().tool_calls) == ["0", "1", "2", "10", "a"]


def test_tool_calls_follow_js_order_again_after_a_budget_reset_owner_ruling_q6() -> None:
    budget = create_budget()
    for name in ["10", "2", "a", "1"]:
        budget.record(_call(name), 0)
    budget.reset()
    for name in ["b", "1", "a", "0"]:
        budget.record(_call(name), 0)
    assert list(budget.state.tool_calls) == ["0", "1", "b", "a"]
