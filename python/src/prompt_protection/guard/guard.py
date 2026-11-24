"""The core tool-call guard (twin of src/guard/guard.ts, plan D1, D2, D40, owner decision 2).

Tool results enter through ``taint``, user turns through ``trust`` and ``analyze_user_turn``, and every
model-proposed call goes through ``check_tool_call``. Only the 4.0 surface is here.
"""

import time
from collections.abc import Callable, Collection, Mapping
from typing import Any, cast

from prompt_protection._js import utf16_len, utf16_slice
from prompt_protection.analyze import AnalysisResult, failed_analysis
from prompt_protection.errors import DeferredFeatureError
from prompt_protection.guard._types import (
    FailMode,
    GuardDecision,
    GuardPolicy,
    SinkResolver,
    SourceInjection,
    TaintedSource,
    ToolCall,
)
from prompt_protection.guard.check import CheckContext, check_tool_call
from prompt_protection.guard.policy import DEFAULT_POLICIES
from prompt_protection.guard.provenance import (
    FlowThresholds,
    SourceIndex,
    TrustState,
    identifier_values,
    stringify_value,
)
from prompt_protection.guard.sinks import create_sink_resolver
from prompt_protection.normalizer import normalize
from prompt_protection.session import ProtectionSession, create_protection_session
from prompt_protection.shingle import build_shingles

__all__ = ["Guard", "create_guard"]

DEFAULT_MAX_SOURCES = 64
DEFAULT_MAX_SOURCE_CHARS = 200_000
DEFAULT_MIN_CONTAINMENT = 0.5
DEFAULT_MIN_CHAR_CONTAINMENT = 0.6
MAX_TRUST_TEXT = 50_000
RECENT_MAX = 64
_DEFAULT_THRESHOLD = 35


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _own_label(injection: SourceInjection) -> str:
    return "blocked" if injection.action == "block" else "tool"


def _has_eddsa_key(memory: Mapping[str, Any] | None) -> bool:
    key = None if memory is None else memory.get("key")
    keys = key if isinstance(key, (list, tuple)) else [key]
    return any(isinstance(k, Mapping) and k.get("alg") == "EdDSA" for k in keys)


def _reject_ml(ml: object) -> None:
    if ml not in (None, "off"):
        raise DeferredFeatureError(f"prompt-protection: ml={ml!r} is not supported in the Python package, use ml='off'")


def _reject_deferred(
    spotlight: object,
    analyze_options: Mapping[str, Any],
    memory: Mapping[str, Any] | None,
    session: ProtectionSession | None,
) -> None:
    if spotlight is not None:
        raise DeferredFeatureError("prompt-protection: the spotlight option is not supported in the Python package yet")
    if "ml" in analyze_options:
        _reject_ml(analyze_options["ml"])
    elif session is not None:
        _reject_ml(session._default_ml)
    if _has_eddsa_key(memory):
        raise DeferredFeatureError("prompt-protection: an EdDSA memory key is not supported in the Python package yet")


class Guard:
    """Build it with ``create_guard``. It holds the tainted sources, the trusted user text and the turn."""

    def __init__(
        self,
        *,
        session: ProtectionSession,
        analyze_options: dict[str, Any],
        resolve_sink: Callable[[str], str],
        policies: tuple[GuardPolicy, ...] | list[GuardPolicy],
        thresholds: FlowThresholds,
        max_sources: int,
        max_source_chars: int,
        trusted_identifiers: tuple[str, ...],
        fail_mode: FailMode,
    ) -> None:
        self._session = session
        self._analyze_options = analyze_options
        self._resolve_sink = resolve_sink
        self._policies = policies
        self._thresholds = thresholds
        self._max_sources = max_sources
        self._max_source_chars = max_source_chars
        self._trusted_identifiers = trusted_identifiers
        self._fail_mode = fail_mode
        self._index = SourceIndex(max_sources, max_source_chars)
        self._trust = TrustState(set(trusted_identifiers), "")
        self._plan: frozenset[str] | None = None
        self._turn = 0
        self._seq = 0
        self._recent: dict[str, GuardDecision] = {}

    @property
    def session(self) -> ProtectionSession:
        return self._session

    @property
    def sources(self) -> list[TaintedSource]:
        return cast(list[TaintedSource], self._index.sources)

    @property
    def turn(self) -> int:
        return self._turn

    @property
    def depth(self) -> int:
        return 0

    def _label_of(self, source_id: str) -> str:
        source = cast(TaintedSource | None, self._index.get(source_id))
        if source is None:
            return "untrusted"
        return source.label if source.label is not None else _own_label(source.injection)

    def taint(self, source: str, value: object, *, id: str | None = None) -> TaintedSource:
        """Register a tool result as untrusted text, scored as an injection. The same ``id`` returns the same source."""
        if id is None:
            self._seq += 1
            id = f"{source}#{self._seq}"
        existing = self._index.get(id)
        if existing is not None:
            return cast(TaintedSource, existing)
        text = utf16_slice(stringify_value(value), 0, self._max_source_chars)
        normalized = normalize(text).normalized
        try:
            result = self._session.analyze(text, **{**self._analyze_options, "analyze_roles": "all"})
        except Exception as err:
            threshold = self._analyze_options.get("threshold")
            result = failed_analysis(err, self._fail_mode, _DEFAULT_THRESHOLD if threshold is None else threshold)
        injection = SourceInjection(score=result.score, action=result.action, categories=list(result.categories))
        entry = TaintedSource(
            id=id,
            tool=source,
            text=text,
            normalized=normalized,
            shingles=build_shingles(normalized, 1),
            identifiers=identifier_values(text),
            injection=injection,
            turn=self._turn,
            timestamp=_now_ms(),
        )
        return cast(TaintedSource, self._index.add(entry))

    def trust(self, text: str) -> None:
        """Record user-authored text. A destination found in it is no longer a flow."""
        normalized = normalize(text).normalized
        self._trust.identifiers.update(identifier_values(text))
        joined = f"{self._trust.text}\n{normalized}" if self._trust.text else normalized
        length = utf16_len(joined)
        self._trust.text = utf16_slice(joined, length - MAX_TRUST_TEXT) if length > MAX_TRUST_TEXT else joined

    def analyze_user_turn(self, prompt: str, **options: Any) -> AnalysisResult:
        """Trust ``prompt`` first, even a blocked one, then score it through the session."""
        self.trust(prompt)
        return self._session.analyze(prompt, **{**self._analyze_options, **options})

    def check_tool_call(self, call: ToolCall) -> GuardDecision:
        """Decide a tool call. It never raises, and the decision is kept under its ``tool_call_id``."""
        decision = check_tool_call(
            call,
            CheckContext(
                index=self._index,
                trust=self._trust,
                thresholds=self._thresholds,
                policies=self._policies,
                resolve_sink=self._resolve_sink,
                plan=self._plan,
                turn=self._turn,
                analyze_options=self._analyze_options,
                fail_mode=self._fail_mode,
                label_of=self._label_of,
                depth=0,
            ),
        )
        if decision.tool_call_id is not None:
            self._recent.pop(decision.tool_call_id, None)
            self._recent[decision.tool_call_id] = decision
            if len(self._recent) > RECENT_MAX:
                del self._recent[next(iter(self._recent))]
        return decision

    def plan(self, allowed_tools: Collection[str] | None) -> None:
        """Allow only these tools. ``None`` lifts the limit, and an empty collection blocks every tool."""
        self._plan = None if allowed_tools is None else frozenset(allowed_tools)

    def next_turn(self) -> None:
        self._turn += 1

    def clear(self) -> None:
        """Forget sources, trusted text, the plan, the turn, remembered decisions and the session history."""
        self._index = SourceIndex(self._max_sources, self._max_source_chars)
        self._trust = TrustState(set(self._trusted_identifiers), "")
        self._plan = None
        self._turn = 0
        self._recent.clear()
        self._session.clear()

    def last_decision(self, tool_call_id: str | None) -> GuardDecision | None:
        return None if tool_call_id is None else self._recent.get(tool_call_id)


def create_guard(
    *,
    session: ProtectionSession | None = None,
    analyze_options: Mapping[str, Any] | None = None,
    sinks: Mapping[str, str | None] | SinkResolver | None = None,
    policies: tuple[GuardPolicy, ...] | list[GuardPolicy] | None = None,
    min_containment: float | None = None,
    min_char_containment: float | None = None,
    max_sources: int | None = None,
    max_source_chars: int | None = None,
    trusted_identifiers: Collection[str] | None = None,
    spotlight: object = None,
    fail_mode: FailMode = "closed",
    logger: object = None,
    memory: Mapping[str, Any] | None = None,
) -> Guard:
    """Create a tool-call guard.

    ``analyze_options`` holds the ``analyze_prompt`` keywords and is copied. Its own ``fail_mode`` wins
    over the guard's. ``logger`` is accepted and not used yet. Raises ``DeferredFeatureError`` for
    ``spotlight``, for an effective ``ml`` other than ``off`` (the ``analyze_options`` value when that key is
    present, else the passed session's default) and for an EdDSA ``memory`` key, whatever ``fail_mode`` says.
    """
    options = dict(analyze_options or {})
    _reject_deferred(spotlight, options, memory, session)
    chosen = session if session is not None else create_protection_session(**options)
    if options.get("fail_mode") is None:
        options["fail_mode"] = fail_mode
    return Guard(
        session=chosen,
        analyze_options=options,
        resolve_sink=create_sink_resolver(sinks),
        policies=DEFAULT_POLICIES if policies is None else policies,
        thresholds=FlowThresholds(
            DEFAULT_MIN_CONTAINMENT if min_containment is None else min_containment,
            DEFAULT_MIN_CHAR_CONTAINMENT if min_char_containment is None else min_char_containment,
        ),
        max_sources=DEFAULT_MAX_SOURCES if max_sources is None else max_sources,
        max_source_chars=DEFAULT_MAX_SOURCE_CHARS if max_source_chars is None else max_source_chars,
        trusted_identifiers=tuple(s.lower() for s in trusted_identifiers or ()),
        fail_mode=fail_mode,
    )
