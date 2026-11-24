"""Policy-facing guard types (twin of the PolicyContext part of src/guard/types.ts, plan D2, D40).

Nested records are structural: a policy reads them by attribute only, so the tasks that own
Flow, TaintedSource and LockView stay free to define those classes.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol

from prompt_protection.analyze import AnalysisResult
from prompt_protection.guard.provenance import Flow
from prompt_protection.shingle import OrderedHashSet, ShingleSet
from prompt_protection.verdict import Action

__all__ = [
    "ApprovalLike",
    "ArgsAnalysisLike",
    "BlockedDecision",
    "BudgetLike",
    "DriftLike",
    "FailMode",
    "FlowLike",
    "GuardDecision",
    "GuardPolicy",
    "InjectionHolder",
    "LineageEdgeLike",
    "LockLike",
    "PolicyAction",
    "PolicyContext",
    "SinkKind",
    "SinkResolver",
    "SourceInjection",
    "SourceLike",
    "TaintedSource",
    "ToolCall",
]

SinkKind = str
PolicyAction = Literal["allow", "flag", "confirm", "block"]
FailMode = Literal["open", "closed"]
SinkResolver = Callable[[str], str | None]


class LineageEdgeLike(Protocol):
    @property
    def from_(self) -> str: ...


class FlowLike(Protocol):
    @property
    def kind(self) -> str: ...

    @property
    def source_id(self) -> str: ...

    @property
    def identifier_kind(self) -> str | None: ...


class _Injection(Protocol):
    @property
    def action(self) -> str: ...


class InjectionHolder(Protocol):
    @property
    def injection(self) -> _Injection: ...


class SourceLike(InjectionHolder, Protocol):
    @property
    def lineage(self) -> Sequence[LineageEdgeLike] | None: ...


class ArgsAnalysisLike(Protocol):
    @property
    def action(self) -> str: ...


class ApprovalLike(Protocol):
    @property
    def status(self) -> str: ...


class DriftLike(Protocol):
    @property
    def kind(self) -> str: ...


class LockLike(Protocol):
    @property
    def locked(self) -> bool: ...

    @property
    def listed(self) -> bool: ...

    @property
    def drift(self) -> DriftLike | None: ...

    @property
    def drift_action(self) -> PolicyAction | None: ...


class BudgetLike(Protocol):
    @property
    def exceeded(self) -> Sequence[str]: ...

    @property
    def on_exceed(self) -> PolicyAction: ...


class BlockedDecision(Protocol):
    @property
    def tool_name(self) -> str: ...

    @property
    def policy(self) -> str | None: ...

    @property
    def sink(self) -> str: ...

    @property
    def flows(self) -> Sequence[object]: ...


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    args: object
    tool_call_id: str | None = None


@dataclass(frozen=True)
class PolicyContext:
    """What a policy sees for one tool call; ``label_of`` answers ``blocked`` for an injection-scored source."""

    call: ToolCall
    sink: SinkKind
    flows: Sequence[FlowLike]
    sources: Sequence[SourceLike]
    turn_sources: Sequence[InjectionHolder]
    args_analysis: ArgsAnalysisLike
    plan: frozenset[str] | None
    destination_trusted: bool
    source_by_id: Callable[[str], SourceLike | None]
    label_of: Callable[[str], str]
    depth: int
    approval: ApprovalLike | None
    lock: LockLike
    budget: BudgetLike | None
    require_lock: bool


class GuardPolicy(Protocol):
    @property
    def id(self) -> str: ...

    def evaluate(self, ctx: PolicyContext) -> PolicyAction | None:
        """Return the action this policy demands, or ``None`` when it does not apply."""
        ...


@dataclass(frozen=True)
class SourceInjection:
    """How a tool result scored as an injection when it was tainted."""

    score: float
    action: str
    categories: list[str]
    ml_probability: float | None = None


@dataclass(kw_only=True)
class TaintedSource:
    """A registered tool result. ``SourceIndex.add`` stores a copy and sets ``word_hashes`` and ``char_hashes``."""

    id: str
    tool: str
    text: str
    normalized: str
    shingles: ShingleSet
    identifiers: Mapping[str, str]
    injection: SourceInjection
    turn: int
    timestamp: int
    label: str | None = None
    lineage: Sequence[LineageEdgeLike] | None = None
    word_hashes: OrderedHashSet = field(init=False, repr=False, compare=False)
    char_hashes: OrderedHashSet = field(init=False, repr=False, compare=False)


@dataclass(frozen=True, kw_only=True)
class GuardDecision:
    """The verdict for one tool call. ``policy`` is ``None`` when the call is allowed."""

    action: Action
    requires_confirmation: bool
    tool_name: str
    tool_call_id: str | None = None
    sink: SinkKind
    flows: list[Flow]
    reasons: list[str]
    policy: str | None = None
    args_analysis: AnalysisResult
    depth: int
