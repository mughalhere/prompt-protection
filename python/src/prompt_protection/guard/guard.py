"""The core tool-call guard (twin of src/guard/guard.ts, plan D1, D2, D40, owner decision 2).

Tool results enter through ``taint``, user turns through ``trust`` and ``analyze_user_turn``, and every
model-proposed call goes through ``check_tool_call``. Memory lineage is here too. Later tasks add the rest.
"""

import math
import time
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from datetime import datetime, timezone
from itertools import islice
from typing import Any, Literal, cast

from prompt_protection._js import utf16_len, utf16_slice
from prompt_protection._rules import RULES_VERSION
from prompt_protection.analyze import AnalysisResult, failed_analysis
from prompt_protection.errors import DeferredFeatureError
from prompt_protection.guard._types import (
    FailMode,
    GuardDecision,
    GuardPolicy,
    LineageEdgeLike,
    SinkResolver,
    SourceInjection,
    TaintedSource,
    ToolCall,
)
from prompt_protection.guard.check import CheckContext, check_tool_call
from prompt_protection.guard.handoff import (
    HandoffSource,
    TaintHandoff,
    _lineage_from_wire,
    _lineage_to_wire,
    assert_taint_handoff,
)
from prompt_protection.guard.memory import (
    MIN_EDGE,
    STRONG_EDGE,
    LineageEdge,
    MemoryEntry,
    MemoryReadResult,
    MemoryWriteResult,
    derive_label,
    is_memory_entry,
    max_label,
)
from prompt_protection.guard.pin import (
    UNLOCKED,
    DriftAction,
    LockState,
    LockView,
    ToolDrift,
    ToolLock,
    ToolSet,
    identity_text,
    is_tool_lock,
    pin_tools,
    tool_identities,
    verify_tools,
)
from prompt_protection.guard.policy import DEFAULT_POLICIES
from prompt_protection.guard.provenance import (
    FlowThresholds,
    SourceIndex,
    TrustState,
    _stringify_flagged,
    containment_of,
    identifier_values,
)
from prompt_protection.guard.sinks import create_sink_resolver, default_sink
from prompt_protection.guard.wrap import WrapHooks, wrap_tools
from prompt_protection.logging_ import LoggingOptions, LogLevel, ProtectionLogger
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


def _iso_ms(ms: int) -> str:
    stamp = datetime.fromtimestamp(ms // 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{stamp}.{ms % 1000:03d}Z"


def _injection_wire(injection: SourceInjection) -> dict[str, Any]:
    out: dict[str, Any] = {
        "score": injection.score,
        "action": injection.action,
        "categories": list(injection.categories),
    }
    if injection.ml_probability is not None:
        out["mlProbability"] = injection.ml_probability
    return out


def _js_max(first: float, second: float) -> float:
    """``Math.max``: a NaN on either side gives NaN."""
    return math.nan if math.isnan(first) or math.isnan(second) else max(first, second)


def _has_eddsa_key(memory: Mapping[str, Any] | None) -> bool:
    key = None if memory is None else memory.get("key")
    keys = key if isinstance(key, (list, tuple)) else [key]
    return any(isinstance(k, Mapping) and k.get("alg") == "EdDSA" for k in keys)


def _explicit_sink(sinks: Mapping[str, str | None] | SinkResolver | None) -> Callable[[str], str | None]:
    if callable(sinks):
        return sinks
    table: Mapping[str, str | None] = {} if sinks is None else sinks
    return table.get


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
        explicit_sink: Callable[[str], str | None],
        policies: tuple[GuardPolicy, ...] | list[GuardPolicy],
        thresholds: FlowThresholds,
        max_sources: int,
        max_source_chars: int,
        max_memory_entries: int,
        trusted_identifiers: tuple[str, ...],
        fail_mode: FailMode,
        logging: LoggingOptions,
        require_lock: bool,
        annotations_default: Literal["destructive", "heuristic"],
        fork_options: Mapping[str, Any],
        inherit: TaintHandoff | None,
    ) -> None:
        self._session = session
        self._analyze_options = analyze_options
        self._resolve_sink = resolve_sink
        self._explicit_sink = explicit_sink
        self._policies = policies
        self._thresholds = thresholds
        self._max_sources = max_sources
        self._max_source_chars = max_source_chars
        self._max_memory_entries = max_memory_entries
        self._trusted_identifiers = trusted_identifiers
        self._fail_mode = fail_mode
        self._logging = logging
        self._require_lock = require_lock
        self._annotations_default = annotations_default
        self._index = SourceIndex(max_sources, max_source_chars)
        self._trust = TrustState(set(trusted_identifiers), "")
        self._trusted_order: dict[str, None] = dict.fromkeys(trusted_identifiers)
        self._fork_options = fork_options
        self._inherit = inherit
        self._plan: frozenset[str] | None = None
        self._turn = 0
        self._depth = 0
        self._seq = 0
        self._recent: dict[str, GuardDecision] = {}
        self._lock: ToolLock | None = None
        self._drift_action: DriftAction = "block"
        self._identities: dict[str, str] = {}
        self._drift: dict[str, ToolDrift] = {}

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
        """Hops from the root guard. ``absorb`` sets it to the larger of its own and the handoff's plus one."""
        return self._depth

    def _label_of(self, source_id: str) -> str:
        source = cast(TaintedSource | None, self._index.get(source_id))
        if source is None:
            return "untrusted"
        return source.label if source.label is not None else _own_label(source.injection)

    def taint(self, source: str, value: object, *, id: str | None = None) -> TaintedSource:
        """Register a tool result as untrusted text, scored as an injection. The same ``id`` returns the same source."""
        return self._taint(source, value, id=id)

    def _taint(
        self,
        source: str,
        value: object,
        *,
        id: str | None,
        label: str | None = None,
        lineage: Sequence[LineageEdgeLike] | None = None,
    ) -> TaintedSource:
        if id is None:
            self._seq += 1
            id = f"{source}#{self._seq}"
        existing = self._index.get(id)
        if existing is not None:
            return cast(TaintedSource, existing)
        rendered, unrenderable = _stringify_flagged(value)
        text = utf16_slice(rendered, 0, self._max_source_chars)
        normalized = normalize(text).normalized
        try:
            result = self._session.analyze(text, **{**self._analyze_options, "analyze_roles": "all"})
        except Exception as err:
            threshold = self._analyze_options.get("threshold")
            result = failed_analysis(err, self._fail_mode, _DEFAULT_THRESHOLD if threshold is None else threshold)
        injection = SourceInjection(score=result.score, action=result.action, categories=list(result.categories))
        own = _own_label(injection)
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
            label=None if label is None else max_label(own, label),
            lineage=lineage,
            unrenderable=unrenderable,
        )
        return cast(TaintedSource, self._index.add(entry))

    def _auto_edges(self, text: str, self_id: str) -> list[LineageEdge]:
        """Containment of ``text`` in each live source other than ``self_id``, as ``derive`` edges."""
        edges: list[LineageEdge] = []
        for src in self._index.sources:
            if src.id == self_id:
                continue
            found = containment_of(text, src.normalized)
            strength = max(found.word, found.char)
            if strength >= MIN_EDGE:
                edges.append(LineageEdge(from_=src.id, kind="derive", strength=strength))
        return edges

    def taint_memory_write(
        self,
        source: str,
        value: object,
        *,
        id: str | None = None,
        policy: Literal["reject-blocked", "annotate"] = "reject-blocked",
        derived_from: Sequence[str] | None = None,
        key: str | None = None,
        label: str | None = None,
    ) -> MemoryWriteResult:
        """Taint a value on its way into memory and return the wire entry to persist.

        ``derived_from`` makes copy edges of strength 1. Without it the edges come from text overlap with the
        live sources. A ``label`` can only raise the label. ``policy`` ``reject-blocked`` sets ``store`` false
        for an injection-scored or blocked-label value.
        """
        src = self._taint(source, value, id=id)
        explicit = [LineageEdge(from_=f, kind="copy", strength=1) for f in derived_from or ()]
        lineage = explicit or self._auto_edges(src.text, src.id)
        derived = derive_label(lineage, self._label_of, _own_label(src.injection))
        resolved = derived if label is None else max_label(derived, label)
        src.label = resolved
        src.lineage = lineage
        entry: MemoryEntry = {
            "v": 1,
            "id": src.id,
            "value": src.text,
            "label": resolved,
            "sourceIds": [e.from_ for e in lineage if e.strength >= STRONG_EDGE],
            "lineage": [{"from": e.from_, "kind": e.kind, "strength": e.strength} for e in lineage],
            "injection": _injection_wire(src.injection),
            "rulesVersion": RULES_VERSION,
            "turn": self._turn,
            "ts": _iso_ms(src.timestamp),
        }
        if key is not None:
            entry = {**entry, "key": key}
        action = src.injection.action
        store = not (policy == "reject-blocked" and (action == "block" or resolved == "blocked"))
        return MemoryWriteResult(source=src, action=action, store=store, entry=entry)

    def memory_read(self, entries: Iterable[MemoryEntry]) -> MemoryReadResult:
        """Register stored entries as sources, re-scored under the current rules. A stored label only raises the result.

        Raises ``TypeError`` for an entry that is not a v1 ``MemoryEntry``. Reads at most ``memory.max_entries``
        entries, which defaults to ``max_sources``.
        """
        sources: list[TaintedSource] = []
        edges: list[LineageEdge] = []
        label = "tool"
        worst = SourceInjection(score=0, action="allow", categories=[])
        for entry in islice(entries, self._max_memory_entries):
            if not is_memory_entry(entry):
                raise TypeError("memory_read: not a v1 MemoryEntry")
            lineage = [LineageEdge(from_=e["from"], kind=e["kind"], strength=e["strength"]) for e in entry["lineage"]]
            lineage.append(LineageEdge(from_=entry["id"], kind="read", strength=1))
            name = entry.get("key")
            src = self._taint(
                f"memory:{entry['id'] if name is None else name}",
                entry["value"],
                id=f"mem:{entry['id']}",
                label=entry["label"],
                lineage=lineage,
            )
            sources.append(src)
            edges.extend(lineage)
            label = max_label(label, src.label if src.label is not None else _own_label(src.injection))
            if src.injection.score > worst.score:
                worst = src.injection
        return MemoryReadResult(sources=sources, label=label, edges=edges, injection=worst)

    def derive(self, value: object, from_source_ids: Sequence[str], *, id: str | None = None) -> TaintedSource:
        """Register a value derived from earlier sources. It takes the highest label among them and its own score."""
        lineage = [LineageEdge(from_=f, kind="derive", strength=1) for f in from_source_ids]
        label = max_label("tool", *(self._label_of(f) for f in from_source_ids))
        return self._taint("derived", value, id=id, label=label, lineage=lineage)

    def trust(self, text: str) -> None:
        """Record user-authored text. A destination found in it is no longer a flow."""
        normalized = normalize(text).normalized
        self._remember_identifiers(identifier_values(text))
        joined = f"{self._trust.text}\n{normalized}" if self._trust.text else normalized
        length = utf16_len(joined)
        self._trust.text = utf16_slice(joined, length - MAX_TRUST_TEXT) if length > MAX_TRUST_TEXT else joined

    def _remember_identifiers(self, values: Iterable[str]) -> None:
        for value in values:
            self._trust.identifiers.add(value)
            self._trusted_order.setdefault(value)

    def analyze_user_turn(self, prompt: str, **options: Any) -> AnalysisResult:
        """Trust ``prompt`` first, even a blocked one, then score it through the session."""
        self.trust(prompt)
        return self._session.analyze(prompt, **{**self._analyze_options, **options})

    def check_tool_call(self, call: ToolCall) -> GuardDecision:
        """Decide a tool call and keep the decision under its ``tool_call_id``.

        An internal failure becomes the ``internal-error`` decision. If the logger raises and
        ``on_logger_error`` raises too, the exception escapes when that decision is logged too. A
        callback that raises for an awaitable result is swallowed.
        """
        decision = check_tool_call(
            call,
            CheckContext(
                index=self._index,
                trust=self._trust,
                thresholds=self._thresholds,
                policies=self._policies,
                resolve_sink=self._resolve_sink_locked,
                plan=self._plan,
                turn=self._turn,
                analyze_options=self._analyze_options,
                fail_mode=self._fail_mode,
                label_of=self._label_of,
                depth=self._depth,
                logging=self._logging,
                lock_of=self._lock_of,
                require_lock=self._require_lock,
            ),
        )
        if decision.tool_call_id is not None:
            self._recent.pop(decision.tool_call_id, None)
            self._recent[decision.tool_call_id] = decision
            if len(self._recent) > RECENT_MAX:
                del self._recent[next(iter(self._recent))]
        return decision

    def handoff(self) -> TaintHandoff:
        """Return the taint state a sub-agent's guard can ``absorb``, as a plain dict with the JS keys."""
        sources: list[HandoffSource] = [
            {
                "id": s.id,
                "tool": s.tool,
                "text": s.text,
                "label": self._label_of(s.id),
                "injection": _injection_wire(s.injection),
                "turn": s.turn,
                "lineage": _lineage_to_wire(s.lineage),
            }
            for s in self.sources
        ]
        return {
            "v": 1,
            "depth": self._depth,
            "turn": self._turn,
            "sources": sources,
            "trustedIdentifiers": list(self._trusted_order),
        }

    def absorb(self, handoff: TaintHandoff) -> None:
        """Take a parent's taint state. Raises ``HandoffError`` for anything but a v1 handoff, changing nothing.

        Depth becomes the larger of its own and the handoff's plus one. A source this guard already holds keeps
        its text and takes the less trusted label. Absorbed sources are scored again and take this guard's turn.
        """
        assert_taint_handoff(handoff)
        self._depth = cast(int, _js_max(self._depth, handoff["depth"] + 1))
        self._remember_identifiers(v.lower() for v in handoff["trustedIdentifiers"])
        for wire in handoff["sources"]:
            existing = cast(TaintedSource | None, self._index.get(wire["id"]))
            if existing is not None:
                own = existing.label if existing.label is not None else _own_label(existing.injection)
                existing.label = max_label(own, wire["label"])
                continue
            self._taint(
                wire["tool"],
                wire["text"],
                id=wire["id"],
                label=wire["label"],
                lineage=_lineage_from_wire(wire["lineage"]),
            )

    def fork(self, **options: Any) -> "Guard":
        """Return a guard with this one's options and taint state. An option passed here wins.

        The child gets its own session and turn counter. The lock and the plan stay behind, and
        ``require_lock`` and ``sinks`` carry over. ``inherit`` is always this guard's own handoff.
        """
        return create_guard(**{**self._fork_options, **options, "inherit": self.handoff()})

    def plan(self, allowed_tools: Collection[str] | None) -> None:
        """Allow only these tools. ``None`` lifts the limit, and an empty collection blocks every tool."""
        self._plan = None if allowed_tools is None else frozenset(allowed_tools)

    def next_turn(self) -> None:
        self._turn += 1

    def clear(self) -> None:
        """Forget sources, trusted text, the plan, the turn, remembered decisions and the session history."""
        self._index = SourceIndex(self._max_sources, self._max_source_chars)
        self._trust = TrustState(set(self._trusted_identifiers), "")
        self._trusted_order = dict.fromkeys(self._trusted_identifiers)
        self._plan = None
        self._turn = 0
        self._depth = 0
        self._recent.clear()
        self._session.clear()
        self._lock = None
        self._identities = {}
        self._drift = {}
        if self._inherit is not None:
            self.absorb(self._inherit)

    def wrap_tools(self, tools: Mapping[str, Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
        """Return the tools with each ``execute`` checked first and its result tainted after (sync only).

        After ``pin``, the definitions seen here are compared with the pinned ones, so a redefined tool drifts.
        """
        self._sync_drift(tools)
        return wrap_tools(
            tools, WrapHooks(check=self.check_tool_call, taint=lambda tool, value, id: self.taint(tool, value, id=id))
        )

    def _lock_of(self, tool_name: str) -> LockView:
        if self._lock is None:
            return UNLOCKED
        pinned = self._lock["tools"].get(tool_name)
        return LockView(
            locked=True,
            listed=pinned is not None,
            drift=self._drift.get(tool_name),
            annotations=None if pinned is None else pinned.get("annotations"),
            drift_action=self._drift_action,
        )

    def _resolve_sink_locked(self, tool_name: str) -> str:
        """Under a lock: explicit sink, ``readOnlyHint``, then the heuristic. An unannotated ``none`` is ``unknown``."""
        explicit = self._explicit_sink(tool_name)
        if explicit is not None:
            return explicit
        if self._lock is None:
            return self._resolve_sink(tool_name)
        pinned = self._lock["tools"].get(tool_name)
        unannotated = pinned is None or "annotations" not in pinned
        annotations = None if pinned is None else pinned.get("annotations")
        if isinstance(annotations, Mapping) and annotations.get("readOnlyHint") is True:
            return "none"
        heuristic = default_sink(tool_name)
        if heuristic == "none" and unannotated and self._annotations_default == "destructive":
            return "unknown"
        return heuristic

    def _install_lock(self, lock: ToolLock, drift: DriftAction) -> None:
        self._lock = lock
        self._drift_action = drift
        self._drift = {}

    def _sync_drift(self, tools: ToolSet) -> None:
        if self._lock is None or not self._identities:
            return
        found: dict[str, ToolDrift] = {}
        for name, identity in tool_identities(tools).items():
            expected = self._identities.get(name)
            if expected is None:
                found[name] = ToolDrift(name=name, kind="unlisted")
            elif expected != identity_text(identity):
                found[name] = ToolDrift(name=name, kind="changed")
        self._drift = found

    def pin(self, tools: ToolSet, *, drift: DriftAction = "block") -> ToolLock:
        """Digest the tool definitions (never ``execute``), install the lock and return it for persisting.

        ``drift`` picks the verdict for a tool whose definition changed: ``block`` or ``confirm``.
        """
        lock = pin_tools(tools)
        self._identities = {name: identity_text(identity) for name, identity in tool_identities(tools).items()}
        self._install_lock(lock, drift)
        return lock

    def lock(self, lock: ToolLock, *, drift: DriftAction = "block") -> None:
        """Install a persisted lock. Drift is detected on the next ``verify``, or ``wrap_tools`` after ``pin``.

        Raises ``TypeError`` for a value that is not a v1 ``ToolLock``.
        """
        if not is_tool_lock(lock):
            raise TypeError("lock: not a v1 ToolLock")
        self._identities = {}
        self._install_lock(lock, drift)

    def verify(self, tools: ToolSet) -> list[ToolDrift]:
        """Re-check current definitions against the lock. The result drives ``tool-drift`` until the next call."""
        if self._lock is None:
            return []
        found = verify_tools(tools, self._lock)
        self._drift = {d.name: d for d in found}
        return found

    @property
    def lock_state(self) -> LockState:
        return LockState(lock=self._lock, drift=list(self._drift.values()), drift_action=self._drift_action)

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
    logger: ProtectionLogger | None = None,
    log_levels: Sequence[LogLevel] | None = None,
    include_content: bool = False,
    max_content_length: int | None = None,
    on_logger_error: Callable[[Exception], None] | None = None,
    memory: Mapping[str, Any] | None = None,
    require_lock: bool = False,
    annotations_default: Literal["destructive", "heuristic"] = "destructive",
    inherit: TaintHandoff | None = None,
) -> Guard:
    """Create a tool-call guard.

    ``analyze_options`` holds the ``analyze_prompt`` keywords and is copied. Its own ``fail_mode`` wins
    over the guard's. ``logger`` and the four options after it log one ``tool-call.*`` event per
    ``check_tool_call``. They are not analyze options, so ``taint`` and ``analyze_user_turn`` log nothing.
    Raises ``DeferredFeatureError`` for ``spotlight``, for an effective ``ml`` other than ``off`` (the
    ``analyze_options`` value when that key is present, else the passed session's default) and for an EdDSA
    ``memory`` key, whatever ``fail_mode`` says. ``memory["max_entries"]`` caps ``memory_read``.
    ``require_lock`` blocks every call until ``pin`` or ``lock`` installs a lock. Under a lock,
    ``annotations_default="destructive"`` makes an unannotated tool the name heuristics call ``none`` an
    ``unknown`` sink, and ``"heuristic"`` keeps ``none``. ``inherit`` absorbs a handoff now and after ``clear``.
    """
    forwarded = {k: v for k, v in locals().items() if k not in ("session", "inherit")}
    options = dict(analyze_options or {})
    _reject_deferred(spotlight, options, memory, session)
    chosen = session if session is not None else create_protection_session(**options)
    if options.get("fail_mode") is None:
        options["fail_mode"] = fail_mode
    sources_cap = DEFAULT_MAX_SOURCES if max_sources is None else max_sources
    memory_cap = None if memory is None else memory.get("max_entries")
    trusted = tuple(s.lower() for s in trusted_identifiers or ())
    forwarded["trusted_identifiers"] = trusted
    guard = Guard(
        session=chosen,
        analyze_options=options,
        resolve_sink=create_sink_resolver(sinks),
        explicit_sink=_explicit_sink(sinks),
        policies=DEFAULT_POLICIES if policies is None else policies,
        thresholds=FlowThresholds(
            DEFAULT_MIN_CONTAINMENT if min_containment is None else min_containment,
            DEFAULT_MIN_CHAR_CONTAINMENT if min_char_containment is None else min_char_containment,
        ),
        max_sources=sources_cap,
        max_source_chars=DEFAULT_MAX_SOURCE_CHARS if max_source_chars is None else max_source_chars,
        max_memory_entries=sources_cap if memory_cap is None else memory_cap,
        trusted_identifiers=trusted,
        fail_mode=fail_mode,
        logging=LoggingOptions(
            logger=logger,
            log_levels=log_levels,
            include_content=include_content,
            max_content_length=max_content_length,
            on_logger_error=on_logger_error,
        ),
        require_lock=require_lock,
        annotations_default=annotations_default,
        fork_options=forwarded,
        inherit=inherit,
    )
    if inherit is not None:
        guard.absorb(inherit)
    return guard
