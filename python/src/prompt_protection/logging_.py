"""Protection events and their emitters, ported from src/logging.ts (PY-12a, owner decision 2).

The module is named ``logging_`` so it never shadows the standard library. ``emit_output_log`` is
deferred (entry e-988d3e). Loggers are sync-only: an awaitable result is reported, never awaited.
"""

import inspect
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, TypedDict

from prompt_protection._js import utf16_len, utf16_slice
from prompt_protection._result import JsResult
from prompt_protection._types import Severity
from prompt_protection.verdict import Action

__all__ = [
    "LogLevel",
    "LoggingOptions",
    "ProtectionEvent",
    "ProtectionLogger",
    "create_console_logger",
    "emit_input_log",
    "emit_tool_call_log",
]

LogLevel = Literal["allowed", "flagged", "blocked", "clean"]
Direction = Literal["input", "tool-call"]

_DEFAULT_LOG_LEVELS: tuple[LogLevel, ...] = ("blocked", "flagged")
_DEFAULT_MAX_CONTENT = 200
_LEVEL_OF: dict[Action, LogLevel] = {"block": "blocked", "flag": "flagged", "allow": "allowed"}


class FlowSummary(TypedDict):
    """One flow as an event carries it. The flow's value never appears."""

    kind: str
    sourceId: str
    sourceTool: str
    path: str
    strength: float


@dataclass(frozen=True, slots=True, kw_only=True)
class ProtectionEvent(JsResult):
    """One logged verdict. A field the JS event leaves absent is ``None``.

    ``to_dict`` gives the JS event JSON: camelCase keys, with a ``None`` field left out and an empty
    list or string kept.

    ``content_preview`` is for the output direction, whose emitter is deferred (entry e-988d3e).
    """

    type: str
    timestamp: str
    score: float
    action: Action
    severity: Severity
    categories: list[str]
    rule_ids: list[str]
    direction: Direction
    tool_name: str | None = None
    tool_call_id: str | None = None
    policy: str | None = None
    reasons: list[str] | None = None
    sink: str | None = None
    flows: list[FlowSummary] | None = None
    error: str | None = None
    mode: str | None = None
    observed_action: str | None = None
    prompt_preview: str | None = None
    content_preview: str | None = None


class ProtectionLogger(Protocol):
    """A sink for events. A logger that also has ``log_with_content(event, content)`` gets that call instead.

    ``content`` is the scanned text before it is truncated into the preview. Both methods are
    sync-only: an awaitable result is never awaited. It is reported through ``on_logger_error``.
    """

    def log(self, event: ProtectionEvent) -> None: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class LoggingOptions:
    """Logging settings. ``log_levels`` defaults to ``blocked`` and ``flagged``, the preview limit to 200 units."""

    logger: ProtectionLogger | None = None
    log_levels: Sequence[LogLevel] | None = None
    include_content: bool = False
    max_content_length: int | None = None
    on_logger_error: Callable[[Exception], None] | None = None
    """Called once with each exception a logger raises, and with a ``TypeError`` for an awaitable result."""


class _RuleLike(Protocol):
    @property
    def id(self) -> str: ...


class _MatchLike(Protocol):
    @property
    def rule(self) -> _RuleLike: ...


class _ErrorLike(Protocol):
    @property
    def message(self) -> str: ...


class _AnalysisLike(Protocol):
    @property
    def score(self) -> float: ...

    @property
    def severity(self) -> Severity: ...

    @property
    def categories(self) -> Sequence[str]: ...

    @property
    def action(self) -> Action: ...

    @property
    def matches(self) -> Sequence[_MatchLike]: ...

    @property
    def error(self) -> _ErrorLike | None: ...


class _FlowLike(Protocol):
    @property
    def kind(self) -> str: ...

    @property
    def source_id(self) -> str: ...

    @property
    def source_tool(self) -> str: ...

    @property
    def path(self) -> str: ...

    @property
    def strength(self) -> float: ...


class ToolCallEventSource(Protocol):
    """A guard decision as the logger sees it. ``mode`` and ``observed_action`` are read when present (PY-19)."""

    @property
    def action(self) -> Action: ...

    @property
    def tool_name(self) -> str: ...

    @property
    def tool_call_id(self) -> str | None: ...

    @property
    def policy(self) -> str | None: ...

    @property
    def reasons(self) -> Sequence[str] | None: ...

    @property
    def sink(self) -> str | None: ...

    @property
    def flows(self) -> Sequence[_FlowLike] | None: ...

    @property
    def args_analysis(self) -> _AnalysisLike: ...


def _timestamp() -> str:
    now = datetime.now(timezone.utc)
    return f"{now:%Y-%m-%dT%H:%M:%S}.{now.microsecond // 1000:03d}Z"


def _event_type(direction: Direction, action: Action) -> str:
    return f"{direction}.{_LEVEL_OF[action]}"


def _truncate(text: str, limit: int) -> str:
    if utf16_len(text) <= limit:
        return text
    return utf16_slice(text, 0, limit) + "…"


def _should_log(action: Action, options: LoggingOptions) -> bool:
    levels = _DEFAULT_LOG_LEVELS if options.log_levels is None else options.log_levels
    return _LEVEL_OF[action] in levels


def _preview(content: str, options: LoggingOptions) -> str | None:
    if options.include_content is not True:
        return None
    limit = _DEFAULT_MAX_CONTENT if options.max_content_length is None else options.max_content_length
    return _truncate(content, limit)


def _emit_safe(logger: ProtectionLogger, event: ProtectionEvent, options: LoggingOptions, content: str) -> None:
    try:
        with_content: Callable[[ProtectionEvent, str], Any] | None = getattr(logger, "log_with_content", None)
        if with_content is not None:
            result = with_content(event, content)
        else:
            log: Callable[[ProtectionEvent], Any] = logger.log
            result = log(event)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise TypeError("a logger returned an awaitable: loggers are sync-only and the result is not awaited")
    except Exception as error:
        if options.on_logger_error is not None:
            options.on_logger_error(error)


def _summarize_flows(flows: Sequence[_FlowLike]) -> list[FlowSummary]:
    return [
        {"kind": f.kind, "sourceId": f.source_id, "sourceTool": f.source_tool, "path": f.path, "strength": f.strength}
        for f in flows
    ]


def emit_input_log(result: _AnalysisLike, content: str, options: LoggingOptions) -> None:
    """Log an input verdict when ``options.logger`` is set and the verdict's level is listed.

    ``content`` is the scanned text. With no logger nothing is read from ``result``.
    """
    logger = options.logger
    if logger is None or not _should_log(result.action, options):
        return
    event = ProtectionEvent(
        type=_event_type("input", result.action),
        timestamp=_timestamp(),
        score=result.score,
        action=result.action,
        severity=result.severity,
        categories=list(result.categories),
        rule_ids=[m.rule.id for m in result.matches],
        direction="input",
        prompt_preview=_preview(content, options),
        error=result.error.message if result.error else None,
    )
    _emit_safe(logger, event, options, content)


def emit_tool_call_log(decision: ToolCallEventSource, args_text: str, options: LoggingOptions) -> None:
    """Log a ``tool-call.*`` event for a guard decision when ``options.logger`` is set and its level is listed.

    The score, severity, categories and rule ids come from ``decision.args_analysis``. With no logger
    nothing is read from ``decision``.
    """
    logger = options.logger
    if logger is None or not _should_log(decision.action, options):
        return
    analysis = decision.args_analysis
    flows = decision.flows
    event = ProtectionEvent(
        type=_event_type("tool-call", decision.action),
        timestamp=_timestamp(),
        score=analysis.score,
        action=decision.action,
        severity=analysis.severity,
        categories=list(analysis.categories),
        rule_ids=[m.rule.id for m in analysis.matches],
        direction="tool-call",
        prompt_preview=_preview(args_text, options),
        tool_name=decision.tool_name,
        tool_call_id=decision.tool_call_id,
        policy=decision.policy,
        reasons=None if decision.reasons is None else list(decision.reasons),
        sink=decision.sink,
        flows=None if flows is None else _summarize_flows(flows),
        mode=getattr(decision, "mode", None),
        observed_action=getattr(decision, "observed_action", None),
        error=analysis.error.message if analysis.error else None,
    )
    _emit_safe(logger, event, options, args_text)


class _ConsoleLogger:
    def log(self, event: ProtectionEvent) -> None:
        print(
            "[prompt-protection]",
            event.type,
            {"score": event.score, "action": event.action, "categories": event.categories, "ruleIds": event.rule_ids},
        )


def create_console_logger() -> ProtectionLogger:
    """Return a logger that prints each event to stdout. Twin of ``createConsoleLogger`` in src/logging.ts.

    The line is ``[prompt-protection]``, the event type, then a dict of ``score``, ``action``,
    ``categories`` and ``ruleIds``. The dict keeps the JS key names.
    """
    return _ConsoleLogger()
