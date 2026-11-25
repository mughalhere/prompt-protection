"""RED tests for create_console_logger and the sync-only logger contract (PY-12c, owner decision 2026-11-24 "Split").

Twin of createConsoleLogger in src/logging.ts. Expected values come from Node 22 running dist/index.js and
dist/guard/index.js. The Python print form is a choice the spec leaves open: the JS line with the object
printed as a Python dict that keeps the JS key names.
"""

import asyncio
import gc
import inspect
import warnings
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from logging_support import ALL_LEVELS, ATTACK, BENIGN, ErrorSink, RaisingLogger, Recorder

import prompt_protection
from prompt_protection import analyze_prompt, create_console_logger
from prompt_protection import logging_ as logging_module
from prompt_protection.guard._types import ToolCall
from prompt_protection.guard.guard import create_guard
from prompt_protection.logging_ import ProtectionEvent

URL = "https://collect.evil-metrics.net/i"
SOURCE = "visit https://collect.evil-metrics.net/i now"
FLAG_BAND = {"flag_threshold": 20, "threshold": 100}
TAG = "[prompt-protection] "
ATTACK_FIELDS = (
    "'categories': ['prompt-injection', 'tool-poisoning'], "
    "'ruleIds': ['injection-ignore-previous', 'tool-ignore-previous']}\n"
)
BLOCKED_LINE = TAG + "input.blocked {'score': 70, 'action': 'block', " + ATTACK_FIELDS
FLAGGED_LINE = TAG + "input.flagged {'score': 70, 'action': 'flag', " + ATTACK_FIELDS
ALLOWED_LINE = TAG + "input.allowed {'score': 0, 'action': 'allow', 'categories': [], 'ruleIds': []}\n"
TOOL_CALL_LINE = (
    TAG + "tool-call.blocked {'score': 35, 'action': 'block', 'categories': ['data-flow'], "
    "'ruleIds': ['guard-data-flow-identifier', 'guard-data-flow-identifier', 'guard-data-flow-exact']}\n"
)
SYNC_ONLY = "sync-only"


def make_event(**fields: Any) -> ProtectionEvent:
    base: dict[str, Any] = {
        "type": "input.blocked",
        "timestamp": "2026-01-01T00:00:00.000Z",
        "score": 70,
        "action": "block",
        "severity": "high",
        "categories": [],
        "rule_ids": [],
        "direction": "input",
    }
    return ProtectionEvent(**{**base, **fields})


def run_analyze(**options: Any) -> Any:
    return analyze_prompt(ATTACK, **options).to_dict()


def run_guard(**options: Any) -> Any:
    guard = create_guard(**options)
    guard.taint("read_email", SOURCE)
    decision = guard.check_tool_call(ToolCall(tool_name="http_post", args={"url": URL}))
    return (decision.action, decision.policy, decision.sink, decision.reasons)


ENTRY_POINTS = pytest.mark.parametrize("run", [run_analyze, run_guard], ids=["analyze_prompt", "check_tool_call"])


class Thenable:
    """An awaitable that is not a coroutine."""

    def __await__(self) -> Any:
        return iter(())


class AsyncLog:
    async def log(self, event: Any) -> None:
        raise AssertionError("an async logger body is never run")


class AsyncWithContent:
    async def log_with_content(self, event: Any, content: str) -> None:
        raise AssertionError("an async logger body is never run")


class ThenableLog:
    def log(self, event: Any) -> Thenable:
        return Thenable()


class ThenableWithContent:
    def log_with_content(self, event: Any, content: str) -> Thenable:
        return Thenable()


class KeepsCoroutines:
    """A logger that returns a coroutine and keeps it, so a test can read its state."""

    def __init__(self, method: str) -> None:
        self.returned: list[Any] = []
        setattr(self, method, self._make)

    async def _body(self) -> None:
        raise AssertionError("an async logger body is never run")

    def _make(self, *args: Any) -> Any:
        coroutine = self._body()
        self.returned.append(coroutine)
        return coroutine


COROUTINE_LOGGERS = pytest.mark.parametrize(
    "logger_class", [AsyncLog, AsyncWithContent], ids=["async-log", "async-log_with_content"]
)
AWAITABLE_LOGGERS = pytest.mark.parametrize(
    "logger_class",
    [AsyncLog, AsyncWithContent, ThenableLog, ThenableWithContent],
    ids=["async-log", "async-log_with_content", "awaitable-log", "awaitable-log_with_content"],
)


def never_awaited(run: Callable[..., Any], **options: Any) -> list[str]:
    """Run once and return every "never awaited" RuntimeWarning it raised, after a full collection."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        run(**options)
        gc.collect()
    return [
        str(w.message) for w in caught if issubclass(w.category, RuntimeWarning) and "never awaited" in str(w.message)
    ]


def test_create_console_logger_is_exported_from_the_root_and_logging_module() -> None:
    assert "create_console_logger" in prompt_protection.__all__
    assert prompt_protection.create_console_logger is logging_module.create_console_logger


@pytest.mark.parametrize(
    ("event", "line"),
    [
        pytest.param(
            make_event(), TAG + "input.blocked {'score': 70, 'action': 'block', 'categories': [], 'ruleIds': []}\n"
        ),
        pytest.param(
            make_event(type="input.flagged", action="flag", score=70.5, categories=["a", "b"], rule_ids=["x"]),
            TAG + "input.flagged {'score': 70.5, 'action': 'flag', 'categories': ['a', 'b'], 'ruleIds': ['x']}\n",
            id="fractional-score-and-lists",
        ),
    ],
)
def test_console_logger_writes_one_line_with_the_four_fields(
    event: ProtectionEvent, line: str, capsys: pytest.CaptureFixture[str]
) -> None:
    create_console_logger().log(event)
    assert capsys.readouterr() == (line, "")


@pytest.mark.parametrize(
    ("prompt", "options", "line"),
    [
        pytest.param(ATTACK, {}, BLOCKED_LINE, id="blocked"),
        pytest.param(ATTACK, FLAG_BAND, FLAGGED_LINE, id="flagged"),
        pytest.param(BENIGN, {"log_levels": ALL_LEVELS}, ALLOWED_LINE, id="allowed"),
    ],
)
def test_console_logger_prints_the_input_event_of_analyze_prompt(
    prompt: str, options: dict[str, Any], line: str, capsys: pytest.CaptureFixture[str]
) -> None:
    sink = ErrorSink()
    analyze_prompt(prompt, logger=create_console_logger(), on_logger_error=sink, **options)
    assert capsys.readouterr() == (line, "")
    assert sink.errors == []


def test_console_logger_prints_the_tool_call_event_of_the_guard(capsys: pytest.CaptureFixture[str]) -> None:
    sink = ErrorSink()
    assert run_guard(logger=create_console_logger(), on_logger_error=sink)[0] == "block"
    assert capsys.readouterr() == (TOOL_CALL_LINE, "")
    assert sink.errors == []


@ENTRY_POINTS
@AWAITABLE_LOGGERS
def test_an_awaitable_result_is_reported_once_as_a_sync_only_error_and_the_verdict_is_unchanged(
    run: Callable[..., Any], logger_class: type
) -> None:
    baseline = run(logger=Recorder())
    sink = ErrorSink()
    assert run(logger=logger_class(), on_logger_error=sink) == baseline
    [error] = sink.errors
    assert isinstance(error, Exception)
    assert SYNC_ONLY in str(error)


@ENTRY_POINTS
@COROUTINE_LOGGERS
@pytest.mark.parametrize("with_sink", [True, False], ids=["with-on_logger_error", "without-on_logger_error"])
def test_a_coroutine_result_raises_no_never_awaited_warning(
    run: Callable[..., Any], logger_class: type, with_sink: bool
) -> None:
    options = {"on_logger_error": ErrorSink()} if with_sink else {}
    assert never_awaited(run, logger=logger_class(), **options) == []


@ENTRY_POINTS
@pytest.mark.parametrize("method", ["log", "log_with_content"])
def test_the_returned_coroutine_is_closed(run: Callable[..., Any], method: str) -> None:
    logger = KeepsCoroutines(method)
    run(logger=logger, on_logger_error=ErrorSink())
    [coroutine] = logger.returned
    assert inspect.getcoroutinestate(coroutine) == inspect.CORO_CLOSED


class KeepsAwaitables:
    """A logger whose ``method`` returns what ``make`` builds, and keeps it so a test can read its state."""

    def __init__(self, method: str, make: Callable[[], Any]) -> None:
        self.returned: list[Any] = []
        self._make = make
        setattr(self, method, self._call)

    def _call(self, *args: Any) -> Any:
        result = self._make()
        self.returned.append(result)
        return result


class ReturnsValue:
    """A logger whose ``method`` returns a plain value."""

    def __init__(self, method: str, value: Any) -> None:
        self.value = value
        setattr(self, method, self._call)

    def _call(self, *args: Any) -> Any:
        return self.value


async def pending_body() -> None:
    await asyncio.sleep(3600)


@pytest.fixture
def loop() -> Iterator[asyncio.AbstractEventLoop]:
    """A fresh event loop that is never run during a test. Teardown cancels what is left on it, then closes it."""
    event_loop = asyncio.get_event_loop_policy().new_event_loop()
    try:
        yield event_loop
    finally:
        leftover = asyncio.all_tasks(event_loop)
        for task in leftover:
            task.cancel()
        if leftover:
            event_loop.run_until_complete(asyncio.gather(*leftover, return_exceptions=True))
        event_loop.close()


def make_future_or_task(loop: asyncio.AbstractEventLoop, kind: str) -> Any:
    return loop.create_future() if kind == "future" else loop.create_task(pending_body())


@ENTRY_POINTS
@pytest.mark.parametrize("method", ["log", "log_with_content"])
@pytest.mark.parametrize("kind", ["future", "task"])
def test_a_future_or_task_result_is_reported_once_and_is_never_cancelled(
    run: Callable[..., Any], method: str, kind: str, loop: asyncio.AbstractEventLoop
) -> None:
    baseline = run(logger=Recorder())
    logger = KeepsAwaitables(method, lambda: make_future_or_task(loop, kind))
    sink = ErrorSink()
    assert run(logger=logger, on_logger_error=sink) == baseline
    [error] = sink.errors
    assert isinstance(error, Exception)
    assert SYNC_ONLY in str(error)
    [awaitable] = logger.returned
    assert awaitable.cancelled() is False
    assert awaitable.done() is False


@ENTRY_POINTS
@pytest.mark.parametrize("method", ["log", "log_with_content"])
@pytest.mark.parametrize("value", [42, None, {"ok": True}], ids=["int", "none", "dict"])
def test_a_non_awaitable_result_is_never_reported(run: Callable[..., Any], method: str, value: Any) -> None:
    baseline = run(logger=Recorder())
    sink = ErrorSink()
    assert run(logger=ReturnsValue(method, value), on_logger_error=sink) == baseline
    assert sink.errors == []


class RaisingSink:
    """An ``on_logger_error`` callback that raises ``cb-boom-N`` on its Nth call."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, error: Any) -> None:
        self.calls += 1
        raise RuntimeError(f"cb-boom-{self.calls}")


BENIGN_CALL = ToolCall(tool_name="search", args={"query": "weather in Paris"})


def analyze_benign(**options: Any) -> Any:
    return analyze_prompt(BENIGN, **options).to_dict()


def guard_benign(**options: Any) -> Any:
    decision = create_guard(**options).check_tool_call(BENIGN_CALL)
    return (decision.action, decision.policy, decision.sink, decision.reasons)


SCENARIOS = pytest.mark.parametrize(
    ("run", "levels"),
    [
        pytest.param(analyze_benign, ["allowed"], id="analyze_prompt-benign-allowed"),
        pytest.param(analyze_benign, ALL_LEVELS, id="analyze_prompt-benign-all"),
        pytest.param(run_analyze, ALL_LEVELS, id="analyze_prompt-attack-all"),
        pytest.param(guard_benign, ["allowed"], id="check_tool_call-benign-allowed"),
        pytest.param(guard_benign, ALL_LEVELS, id="check_tool_call-benign-all"),
        pytest.param(run_guard, ALL_LEVELS, id="check_tool_call-attack-all"),
    ],
)


def make_awaitable(loop: asyncio.AbstractEventLoop, kind: str) -> Any:
    return pending_body() if kind == "coroutine" else loop.create_future()


@SCENARIOS
@pytest.mark.parametrize("fail_mode", ["closed", "open"])
@pytest.mark.parametrize("kind", ["coroutine", "future"])
def test_a_raising_on_logger_error_for_an_awaitable_result_neither_raises_nor_changes_the_verdict(
    run: Callable[..., Any], levels: list[str], fail_mode: str, kind: str, loop: asyncio.AbstractEventLoop
) -> None:
    baseline = run(logger=Recorder(), fail_mode=fail_mode, log_levels=levels)
    callback = RaisingSink()
    logger = KeepsAwaitables("log", lambda: make_awaitable(loop, kind))
    assert run(logger=logger, on_logger_error=callback, fail_mode=fail_mode, log_levels=levels) == baseline
    assert callback.calls == 1


def test_a_raising_on_logger_error_for_a_raising_logger_still_raises_out_of_the_call() -> None:
    """PY-12a parity row: analyzePrompt benign allowed open cb=always is THROW cb-boom-2, log=2 cb=2."""
    logger = RaisingLogger(RuntimeError("log-boom"))
    callback = RaisingSink()
    with pytest.raises(RuntimeError, match="cb-boom-2"):
        analyze_prompt(BENIGN, logger=logger, on_logger_error=callback, fail_mode="open", log_levels=["allowed"])
    assert (logger.calls, callback.calls) == (2, 2)
