"""Tests for the Python port of datasets/steps.cjs in tests/steps.py (PY-23; plan design item 5, D13, D19).

Most tests drive ``run_row`` through a scripted guard that logs each call, so each op's mapping onto the Python
``Guard`` API is checked apart from guard behaviour. The ``lock`` op, which no dataset row uses, also runs
against a real guard.
"""

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, NamedTuple

import pytest
from steps import CLOCK_START, OPS, Recorder, js_ops, run_row

from prompt_protection.guard import ToolCall, create_guard, pin_tools

DATASET = Path(__file__).resolve().parents[2] / "datasets" / "agent-flows.jsonl"
FINAL = {"toolName": "final", "args": {"x": 1}}
FINAL_CALL = ToolCall(tool_name="final", args={"x": 1})
LOCK = {"v": 1, "algo": "sha256", "createdAt": "2026-01-01T00:00:00.000Z", "rulesVersion": "9", "tools": {"a": {}}}
TOOLS = {
    "a": {"description": "first", "inputSchema": {"type": "object"}},
    "b": {"description": "second", "annotations": {"readOnlyHint": True}},
}
LOCKED_TOOLS = {"send_email": {"description": "Send an email", "inputSchema": {"type": "object"}}}


class ScriptedGuard:
    """Logs every call it gets, with the real ``Guard`` signatures, and returns canned values."""

    depth = 2

    def __init__(self, factory: "Factory", name: str) -> None:
        self.factory = factory
        self.name = name

    def note(self, method: str, *details: Any) -> None:
        self.factory.log.append((self.name, method, *details))

    def analyze_user_turn(self, prompt: str) -> None:
        self.note("analyze_user_turn", prompt)

    def taint(self, source: str, value: object, *, id: str | None = None) -> None:
        self.note("taint", source, value, id)

    def taint_memory_write(
        self,
        source: str,
        value: object,
        *,
        id: str | None = None,
        policy: str = "reject-blocked",
        derived_from: list[str] | None = None,
        key: str | None = None,
    ) -> Any:
        self.note("taint_memory_write", source, value, id, policy, derived_from, key)
        return SimpleNamespace(entry={"entry-of": id})

    def memory_read(self, entries: list[Any]) -> None:
        self.note("memory_read", list(entries))

    def fork(self) -> "ScriptedGuard":
        self.note("fork")
        return ScriptedGuard(self.factory, f"{self.name}>fork")

    def next_turn(self) -> None:
        self.note("next_turn")

    def approval_card(self, call: ToolCall) -> Any:
        self.note("approval_card", call)
        canonical = json.dumps(call.args, sort_keys=True, separators=(",", ":"))
        return SimpleNamespace(id="card-1", digest="sha256:fake", canonical_args=canonical, tool_name=call.tool_name)

    def confirm(self, id: str, digest: str, by: str | None = None) -> None:
        self.note("confirm", id, digest, by)

    def pin(self, tools: dict[str, Any], *, drift: str = "block") -> dict[str, Any]:
        self.note("pin", copy.deepcopy(tools), drift)
        self.factory.pinned.append(tools)
        return LOCK

    def lock(self, lock: dict[str, Any], *, drift: str = "block") -> None:
        self.note("lock", lock, drift)

    def wrap_tools(self, tools: dict[str, Any]) -> None:
        self.note("wrap_tools", copy.deepcopy(tools))

    def record_cost(self, *, usd: float | None = None, tokens: float | None = None) -> None:
        self.note("record_cost", usd, tokens)

    def check_tool_call(self, call: ToolCall) -> tuple[str, int]:
        self.note("check_tool_call", call)
        self.factory.clocks.append(self.factory.options[0]["approvals"]["now"]())
        decision = ("decision", len(self.factory.log))
        self.factory.decisions.append(decision)
        return decision


class Factory:
    def __init__(self) -> None:
        self.log: list[tuple[Any, ...]] = []
        self.options: list[dict[str, Any]] = []
        self.clocks: list[int] = []
        self.decisions: list[tuple[str, int]] = []
        self.pinned: list[dict[str, Any]] = []

    def __call__(self, **options: Any) -> ScriptedGuard:
        self.options.append(options)
        return ScriptedGuard(self, f"g{len(self.options)}")

    def before_final(self) -> list[tuple[Any, ...]]:
        return self.log[:-1]


class Run(NamedTuple):
    factory: Factory
    recorder: Recorder
    decision: Any


def row_of(*steps: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"id": "t-1", "sinks": {}, "call": FINAL, "steps": list(steps), **extra}


def run(row: dict[str, Any]) -> Run:
    factory, recorder = Factory(), Recorder()
    return Run(factory, recorder, run_row(factory, row, recorder))


def step_log(*steps: dict[str, Any]) -> list[tuple[Any, ...]]:
    return run(row_of(*steps)).factory.before_final()


def dataset_ops() -> set[str]:
    rows = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]
    return {step["op"] for row in rows for step in row.get("steps") or []}


def test_ops_equal_the_ops_declared_in_steps_cjs() -> None:
    assert "recordCost" in js_ops()
    assert OPS == js_ops()


def test_every_op_has_a_dataset_row_or_a_lock_test_in_this_file() -> None:
    assert OPS <= dataset_ops() | {"lock"}


@pytest.mark.parametrize("extra", [{}, {"steps": None}], ids=["no-steps-key", "steps-null"])
def test_a_row_without_a_steps_list_is_user_then_sources_then_the_scored_call(extra: dict[str, Any]) -> None:
    row = {"id": "t-1", "user": "hello", "sources": [{"id": "s1", "tool": "mail", "text": "body"}], "call": FINAL}
    result = run({**row, **extra})
    assert result.factory.log == [
        ("g1", "analyze_user_turn", "hello"),
        ("g1", "taint", "mail", "body", "s1"),
        ("g1", "check_tool_call", FINAL_CALL),
    ]
    assert result.decision == result.factory.decisions[-1]


def test_a_row_with_no_user_text_and_no_sources_checks_only_the_call() -> None:
    assert run({"id": "t-1", "call": FINAL}).factory.log == [("g1", "check_tool_call", FINAL_CALL)]


def test_a_steps_row_registers_user_and_sources_before_its_steps_and_returns_the_final_call() -> None:
    sources = [{"id": "s1", "tool": "mail", "text": "body"}]
    result = run(row_of({"op": "call", "toolName": "mid", "args": {}}, user="hello", sources=sources))
    assert [entry[1] for entry in result.factory.log] == [
        "analyze_user_turn",
        "taint",
        "check_tool_call",
        "check_tool_call",
    ]
    assert result.factory.log[2][2].tool_name == "mid"
    assert result.decision == result.factory.decisions[-1] != result.factory.decisions[0]


def test_an_empty_steps_list_still_checks_the_final_call() -> None:
    result = run(row_of())
    assert result.factory.log == [("g1", "check_tool_call", FINAL_CALL)]


OP_CASES = {
    "trust": ({"op": "trust", "text": "mine"}, ("g1", "analyze_user_turn", "mine")),
    "taint-with-id": ({"op": "taint", "tool": "a", "text": "b", "id": "x"}, ("g1", "taint", "a", "b", "x")),
    "taint-without-id": ({"op": "taint", "tool": "a", "text": "b"}, ("g1", "taint", "a", "b", None)),
    "nextTurn": ({"op": "nextTurn"}, ("g1", "next_turn")),
    "call-with-id": (
        {"op": "call", "toolName": "n", "args": {"k": 1}, "toolCallId": "c1"},
        ("g1", "check_tool_call", ToolCall(tool_name="n", args={"k": 1}, tool_call_id="c1")),
    ),
    "call-without-id": (
        {"op": "call", "toolName": "n", "args": {"k": 1}},
        ("g1", "check_tool_call", ToolCall(tool_name="n", args={"k": 1}, tool_call_id=None)),
    ),
    "recordCost-both": ({"op": "recordCost", "cost": {"usd": 0.5, "tokens": 10}}, ("g1", "record_cost", 0.5, 10)),
    "recordCost-tokens": ({"op": "recordCost", "cost": {"tokens": 5000}}, ("g1", "record_cost", None, 5000)),
    "lock": ({"op": "lock", "lock": LOCK}, ("g1", "lock", LOCK, "block")),
    "lock-drift": ({"op": "lock", "lock": LOCK, "drift": "confirm"}, ("g1", "lock", LOCK, "confirm")),
    "pin": ({"op": "pin", "tools": TOOLS}, ("g1", "pin", TOOLS, "block")),
    "pin-drift": ({"op": "pin", "tools": TOOLS, "drift": "confirm"}, ("g1", "pin", TOOLS, "confirm")),
}


@pytest.mark.parametrize(("step", "logged"), OP_CASES.values(), ids=list(OP_CASES))
def test_each_op_calls_the_matching_guard_method_with_the_step_fields(
    step: dict[str, Any], logged: tuple[Any, ...]
) -> None:
    assert step_log(step) == [logged]


@pytest.mark.parametrize(
    ("step", "logged"),
    [
        (
            {"op": "memoryWrite", "id": "m1", "tool": "summarise", "text": "t"},
            ("g1", "taint_memory_write", "summarise", "t", "m1", "annotate", None, None),
        ),
        (
            {
                "op": "memoryWrite",
                "id": "m1",
                "tool": "summarise",
                "text": "t",
                "policy": "reject-blocked",
                "key": "notes/a",
                "derivedFrom": ["mail-1"],
            },
            ("g1", "taint_memory_write", "summarise", "t", "m1", "reject-blocked", ["mail-1"], "notes/a"),
        ),
    ],
    ids=["defaults-to-annotate", "forwards-policy-key-and-derived-from"],
)
def test_memory_write_forwards_its_options_and_defaults_the_policy_to_annotate(
    step: dict[str, Any], logged: tuple[Any, ...]
) -> None:
    assert step_log(step) == [logged]


def test_memory_read_passes_the_entries_the_writes_returned_in_the_order_of_the_ids() -> None:
    writes = [{"op": "memoryWrite", "id": m, "tool": "t", "text": m} for m in ("m1", "m2")]
    log = step_log(*writes, {"op": "memoryRead", "ids": ["m2", "m1"]})
    assert log[-1] == ("g1", "memory_read", [{"entry-of": "m2"}, {"entry-of": "m1"}])


def test_memory_written_before_a_new_guard_can_be_read_by_that_guard() -> None:
    write = {"op": "memoryWrite", "id": "m1", "tool": "t", "text": "x"}
    log = step_log(write, {"op": "newGuard"}, {"op": "memoryRead", "ids": ["m1"]})
    assert log[-1] == ("g2", "memory_read", [{"entry-of": "m1"}])


@pytest.mark.parametrize("ids", [["nope"], ["m1", "nope"]], ids=["none-written", "one-missing"])
def test_memory_read_of_an_unwritten_id_raises_before_reading(ids: list[str]) -> None:
    factory = Factory()
    steps = [{"op": "memoryWrite", "id": "m1", "tool": "t", "text": "x"}, {"op": "memoryRead", "ids": ids}]
    with pytest.raises(ValueError, match=r"^t-1: memoryRead of an unwritten id$"):
        run_row(factory, row_of(*steps))
    assert [entry[1] for entry in factory.log] == ["taint_memory_write"]


def test_an_unknown_op_raises_after_the_earlier_steps_ran_and_before_the_later_ones() -> None:
    factory = Factory()
    steps = [{"op": "trust", "text": "a"}, {"op": "bogus"}, {"op": "trust", "text": "b"}]
    with pytest.raises(ValueError, match=r"^t-1: unknown step op bogus$"):
        run_row(factory, row_of(*steps))
    assert factory.log == [("g1", "analyze_user_turn", "a")]


def test_new_guard_builds_another_guard_from_the_same_options_and_later_ops_go_to_it() -> None:
    result = run(row_of({"op": "newGuard"}, {"op": "taint", "tool": "a", "text": "b"}))
    first, second = result.factory.options
    assert first == second
    assert [entry[:2] for entry in result.factory.log] == [("g2", "taint"), ("g2", "check_tool_call")]


def test_fork_sends_later_ops_to_the_guard_it_returns_and_forks_chain() -> None:
    result = run(row_of({"op": "fork"}, {"op": "fork"}, {"op": "nextTurn"}))
    assert [entry[:2] for entry in result.factory.log] == [
        ("g1", "fork"),
        ("g1>fork", "fork"),
        ("g1>fork>fork", "next_turn"),
        ("g1>fork>fork", "check_tool_call"),
    ]


@pytest.mark.parametrize(
    ("step", "by"),
    [
        ({"op": "approve", "toolName": "stripe", "args": {"amount": 10}, "toolCallId": "p1", "by": "alice"}, "alice"),
        ({"op": "approve", "toolName": "stripe", "args": {"amount": 10}}, None),
    ],
    ids=["with-by-and-call-id", "bare"],
)
def test_approve_issues_a_card_for_the_call_and_confirms_it_with_the_cards_id_and_digest(
    step: dict[str, Any], by: str | None
) -> None:
    call = ToolCall(tool_name="stripe", args={"amount": 10}, tool_call_id=step.get("toolCallId"))
    assert step_log(step) == [("g1", "approval_card", call), ("g1", "confirm", "card-1", "sha256:fake", by)]


def test_pin_hands_the_guard_a_deep_copy_so_the_row_is_never_changed() -> None:
    step = {"op": "pin", "tools": copy.deepcopy(TOOLS)}
    [received] = run(row_of(step)).factory.pinned
    assert received == step["tools"]
    assert received is not step["tools"]
    assert received["a"] is not step["tools"]["a"]
    assert received["a"]["inputSchema"] is not step["tools"]["a"]["inputSchema"]


def test_redefine_tool_merges_into_the_pinned_definitions_and_re_wraps_every_tool() -> None:
    first = {"op": "redefineTool", "name": "a", "tool": {"description": "changed"}}
    second = {"op": "redefineTool", "name": "a", "tool": {"annotations": {"destructiveHint": True}}}
    log = step_log({"op": "pin", "tools": TOOLS}, first, second)
    merged_once = {**TOOLS, "a": {**TOOLS["a"], "description": "changed"}}
    merged_twice = {**merged_once, "a": {**merged_once["a"], "annotations": {"destructiveHint": True}}}
    assert [entry[1:] for entry in log[1:]] == [("wrap_tools", merged_once), ("wrap_tools", merged_twice)]


def test_redefine_tool_without_a_pin_wraps_just_the_new_definition() -> None:
    log = step_log({"op": "redefineTool", "name": "n", "tool": {"description": "d"}})
    assert log == [("g1", "wrap_tools", {"n": {"description": "d"}})]


def test_the_definitions_a_row_redefines_carry_over_to_a_new_guard() -> None:
    log = step_log({"op": "pin", "tools": TOOLS}, {"op": "newGuard"}, {"op": "redefineTool", "name": "b", "tool": {}})
    assert log[-1] == ("g2", "wrap_tools", TOOLS)


def test_options_are_passed_to_create_guard_with_python_keyword_names_and_the_row_sinks() -> None:
    options = {
        "budgets": {"maxCallsPerTool": {"slack_post": 2}, "maxCost": {"tokens": 4000}},
        "approvals": {"ttlMs": 5},
    }
    [passed] = run(row_of(options=options, sinks={"send": "email"})).factory.options
    assert passed.pop("approvals").pop("now")() == CLOCK_START
    assert passed == {
        "budgets": {"max_calls_per_tool": {"slack_post": 2}, "max_cost": {"tokens": 4000}},
        "sinks": {"send": "email"},
    }


def test_a_row_with_no_options_or_sinks_passes_empty_sinks_and_only_the_clock() -> None:
    [passed] = run({"id": "t-1", "call": FINAL}).factory.options
    assert sorted(passed) == ["approvals", "sinks"]
    assert passed["sinks"] == {}
    assert sorted(passed["approvals"]) == ["now"]


def test_the_approval_clock_starts_at_1_7_trillion_and_advance_clock_moves_it() -> None:
    check = {"op": "call", "toolName": "n", "args": {}}
    steps = [check, {"op": "advanceClock", "ms": 700000}, check, {"op": "advanceClock", "ms": 5}]
    assert run(row_of(*steps)).factory.clocks == [CLOCK_START, CLOCK_START + 700000, CLOCK_START + 700005]


def test_approval_cards_are_recorded_in_the_fields_the_golden_stores() -> None:
    approve = {"op": "approve", "toolName": "stripe", "args": {"payee": "acct_1", "amount": 10}}
    result = run(row_of(approve, approve))
    card = {"toolName": "stripe", "digest": "sha256:fake", "canonicalArgs": '{"amount":10,"payee":"acct_1"}'}
    assert result.recorder.cards == [card, card]
    assert result.recorder.locks == []


def test_a_pin_is_recorded_without_its_created_at() -> None:
    result = run(row_of({"op": "pin", "tools": TOOLS}))
    assert result.recorder.locks == [{"v": 1, "algo": "sha256", "rulesVersion": "9", "tools": {"a": {}}}]
    assert result.recorder.cards == []


@pytest.mark.parametrize(
    "lead",
    [[{"op": "fork"}], [{"op": "fork"}, {"op": "fork"}], [{"op": "newGuard"}]],
    ids=["fork", "fork-of-fork", "new-guard"],
)
def test_the_recorder_wraps_every_guard_a_row_creates_or_forks(lead: list[dict[str, Any]]) -> None:
    approve = {"op": "approve", "toolName": "stripe", "args": {}}
    result = run(row_of(*lead, approve, {"op": "pin", "tools": TOOLS}))
    assert len(result.recorder.cards) == 1
    assert len(result.recorder.locks) == 1


def test_a_wrapped_guard_forwards_every_other_member_unchanged() -> None:
    wrapped = Recorder().wrap(ScriptedGuard(Factory(), "g1"))
    assert wrapped.depth == 2
    wrapped.next_turn()
    assert wrapped.factory.log == [("g1", "next_turn")]


def test_a_row_runs_without_a_recorder() -> None:
    factory = Factory()
    row = row_of({"op": "approve", "toolName": "stripe", "args": {}}, {"op": "pin", "tools": TOOLS})
    assert run_row(factory, row) == factory.decisions[-1]


@pytest.mark.parametrize(
    ("tool", "action", "reasons"),
    [("send_email", "allow", []), ("other_tool", "block", ["tool-unpinned"])],
    ids=["listed-tool", "unlisted-tool"],
)
def test_the_lock_op_installs_the_lock_on_a_real_guard(tool: str, action: str, reasons: list[str]) -> None:
    row = {
        "id": "t-1",
        "sinks": {"send_email": "email"},
        "steps": [{"op": "lock", "lock": pin_tools(LOCKED_TOOLS)}],
        "call": {"toolName": tool, "args": {"to": "me@example.com"}},
    }
    decision = run_row(create_guard, row)
    assert (decision.action, decision.reasons) == (action, reasons)
    assert decision.lock is not None and decision.lock.locked
