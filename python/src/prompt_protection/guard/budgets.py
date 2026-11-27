"""Per-guard call and cost budgets (twin of src/guard/budgets.ts)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, TypedDict

from prompt_protection._result import JsResult
from prompt_protection.canonical import digest_sync_weak
from prompt_protection.guard.provenance import _js_key_order

if TYPE_CHECKING:
    from typing_extensions import Unpack

    from prompt_protection.guard._types import ToolCall

__all__ = [
    "Budget",
    "BudgetCost",
    "BudgetOptions",
    "BudgetState",
    "CostLimits",
    "DEFAULT_MAX_REPEAT_IDENTICAL",
    "create_budget",
]

DEFAULT_MAX_REPEAT_IDENTICAL = 3

OnExceed = Literal["block", "confirm"]


class CostLimits(TypedDict, total=False):
    """Cost ceilings, fed by ``Guard.record_cost``."""

    usd: float
    tokens: float


class BudgetOptions(TypedDict, total=False):
    """The keywords of ``create_budget``; an unknown key is ignored, as in JS.

    ``max_calls_per_tool`` is one number for all tools or a mapping per tool name. ``max_repeat_identical``
    defaults to 3 and ``on_exceed`` to ``block``. ``None`` means no limit.
    """

    max_calls_per_turn: float | None
    max_calls_per_tool: float | Mapping[str, float] | None
    max_repeat_identical: float | None
    max_depth: float | None
    max_cost: CostLimits | None
    on_exceed: OnExceed | None


@dataclass
class BudgetCost(JsResult):
    usd: float = 0
    tokens: float = 0


@dataclass
class BudgetState(JsResult):
    """Counts so far. ``repeats`` maps the weak digest of the tool name and arguments to its count.

    ``exceeded`` names each limit passed, such as ``calls-per-tool:http_post`` or ``cost:usd``.
    """

    turn_calls: int = 0
    tool_calls: dict[str, int] = field(default_factory=dict)
    repeats: dict[str, int] = field(default_factory=dict)
    cost: BudgetCost = field(default_factory=BudgetCost)
    depth: int = 0
    exceeded: list[str] = field(default_factory=list)
    on_exceed: OnExceed = "block"


def _limit_for(limit: float | Mapping[str, float] | None, tool_name: str) -> float | None:
    if isinstance(limit, Mapping):
        return limit.get(tool_name)
    return limit


class Budget:
    """Build it with ``create_budget``. ``state`` is the live object; ``reset`` replaces it."""

    def __init__(self, options: Mapping[str, Any]) -> None:
        self._options = options
        repeat = options.get("max_repeat_identical")
        self._max_repeat = DEFAULT_MAX_REPEAT_IDENTICAL if repeat is None else repeat
        on_exceed = options.get("on_exceed")
        self._on_exceed: OnExceed = "block" if on_exceed is None else on_exceed
        self._state = self._fresh()

    def _fresh(self) -> BudgetState:
        return BudgetState(on_exceed=self._on_exceed)

    @property
    def state(self) -> BudgetState:
        return self._state

    def _evaluate(self) -> None:
        state, options = self._state, self._options
        exceeded: list[str] = []
        per_turn = options.get("max_calls_per_turn")
        if per_turn is not None and state.turn_calls > per_turn:
            exceeded.append("calls-per-turn")
        for tool in _js_key_order(list(state.tool_calls)):
            limit = _limit_for(options.get("max_calls_per_tool"), tool)
            if limit is not None and state.tool_calls[tool] > limit:
                exceeded.append(f"calls-per-tool:{tool}")
        if any(n > self._max_repeat for n in state.repeats.values()):
            exceeded.append("repeat-identical")
        max_depth = options.get("max_depth")
        if max_depth is not None and state.depth > max_depth:
            exceeded.append("depth")
        max_cost = options.get("max_cost") or {}
        if max_cost.get("usd") is not None and state.cost.usd > max_cost["usd"]:
            exceeded.append("cost:usd")
        if max_cost.get("tokens") is not None and state.cost.tokens > max_cost["tokens"]:
            exceeded.append("cost:tokens")
        state.exceeded = exceeded

    def _count_tool(self, name: str) -> None:
        """Count one call, keeping ``tool_calls`` in JS key order. Reorders in place."""
        counts = self._state.tool_calls
        is_new = name not in counts
        counts[name] = counts.get(name, 0) + 1
        if is_new:
            ordered = {key: counts[key] for key in _js_key_order(list(counts))}
            counts.clear()
            counts.update(ordered)

    def record(self, call: ToolCall, depth: int) -> BudgetState:
        """Count the attempt, blocked or not, and return the live state the policies see."""
        state = self._state
        state.turn_calls += 1
        self._count_tool(call.tool_name)
        key = digest_sync_weak({"toolName": call.tool_name, "args": call.args})
        state.repeats[key] = state.repeats.get(key, 0) + 1
        state.depth = depth
        self._evaluate()
        return state

    def record_cost(self, *, usd: float | None = None, tokens: float | None = None) -> BudgetState:
        """Add to the cost totals. ``None`` adds nothing."""
        state = self._state
        state.cost.usd += 0 if usd is None else usd
        state.cost.tokens += 0 if tokens is None else tokens
        self._evaluate()
        return state

    def next_turn(self) -> None:
        """Zero ``turn_calls`` only. Tool counts, repeats and cost carry on."""
        self._state.turn_calls = 0
        self._evaluate()

    def reset(self) -> None:
        """Replace the state with a zeroed one. The options stay."""
        self._state = self._fresh()


def create_budget(**options: Unpack[BudgetOptions]) -> Budget:
    """Create a budget from ``BudgetOptions`` keywords."""
    return Budget(options)
