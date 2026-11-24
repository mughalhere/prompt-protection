"""A stateful protection session that escalates deferred-reference follow-ups, ported from src/session.ts."""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any, TypedDict

from prompt_protection._js import utf16_len, utf16_slice
from prompt_protection._rules import _FLAGS, DEFERRED_REFERENCE_RULE_IDS, Rule
from prompt_protection._types import AnalyzeRoles, CustomRule, FailMode, MlMode, PromptInput
from prompt_protection.analyze import (
    DEFAULT_THRESHOLD,
    AnalysisResult,
    analyze_prompt,
    compute_severity,
    strip_prompt,
)
from prompt_protection.errors import PromptInjectionError
from prompt_protection.messages import resolve_prompt_input
from prompt_protection.scorer import PatternMatch

if TYPE_CHECKING:
    from typing_extensions import Unpack

__all__ = ["AnalyzeOptions", "ProtectionSession", "StripOptions", "create_protection_session"]

DEFAULT_MAX_BLOCKED_HISTORY = 5
MAX_STORED_PROMPT_LENGTH = 500

_DEFERRED_IDS = frozenset(DEFERRED_REFERENCE_RULE_IDS)
_CORRELATION_RULE = Rule(
    id="session-correlate-blocked",
    source="(?!)",
    weight=10,
    category="prompt-injection",
    precision="high",
    pattern=re.compile("(?!)", _FLAGS),
    description="Deferred reference to a prior turn correlated with a previously blocked prompt",
)


class AnalyzeOptions(TypedDict, total=False):
    """The keyword options of ``analyze_prompt``."""

    threshold: float
    flag_threshold: float | None
    custom_rules: Sequence[CustomRule] | None
    disabled_categories: Sequence[str] | None
    disabled_rule_ids: Sequence[str] | None
    allowlist_patterns: Sequence[re.Pattern[str]] | None
    allowlist_rule_ids: Sequence[str] | None
    sentence_analysis: bool
    analyze_roles: AnalyzeRoles | None
    max_input_length: int | None
    ml: MlMode | None
    fail_mode: FailMode


class StripOptions(AnalyzeOptions, total=False):
    """The keyword options of ``strip_prompt``."""

    replacement: str
    strip_whole_segment: bool


_STRIP_ONLY = ("replacement", "strip_whole_segment")


def _is_deferred(hit: PatternMatch) -> bool:
    return hit.rule.id in _DEFERRED_IDS


def _truncate_for_history(text: str) -> str:
    if utf16_len(text) <= MAX_STORED_PROMPT_LENGTH:
        return text
    return utf16_slice(text, 0, MAX_STORED_PROMPT_LENGTH) + "…"


def _escalate(result: AnalysisResult, threshold: float) -> AnalysisResult:
    deferred = next(hit for hit in result.matches if _is_deferred(hit))
    synthetic = PatternMatch(_CORRELATION_RULE, deferred.matched_text, deferred.start_index, deferred.end_index)
    escalated = max(result.score, threshold)
    return replace(
        result,
        score=escalated,
        severity=compute_severity(escalated),
        action="block",
        is_malicious=True,
        matches=[*result.matches, synthetic],
        categories=list(dict.fromkeys([*result.categories, "prompt-injection"])),
    )


class ProtectionSession:
    """Remembers recently blocked prompts and blocks a deferred-reference follow-up that comes after one.

    Build it with ``create_protection_session``. Per-call options override the session defaults key by key.
    """

    def __init__(
        self, *, max_blocked_history: int, correlate_blocked: bool, defaults: AnalyzeOptions | dict[str, Any]
    ) -> None:
        if max_blocked_history < 0:
            raise ValueError("prompt-protection: max_blocked_history must not be negative")
        self._correlate_blocked = correlate_blocked
        self._defaults: dict[str, Any] = dict(defaults)
        self._blocked: deque[str] = deque(maxlen=max_blocked_history)

    def _analyze(self, prompt: PromptInput, merged: dict[str, Any]) -> AnalysisResult:
        options = {key: value for key, value in merged.items() if key not in _STRIP_ONLY}
        threshold = options.get("threshold")
        if threshold is None:
            threshold = DEFAULT_THRESHOLD
        result = analyze_prompt(prompt, **options)
        if (
            self._correlate_blocked
            and self._blocked
            and result.action != "block"
            and any(_is_deferred(hit) for hit in result.matches)
        ):
            result = _escalate(result, threshold)
        if result.action == "block":
            text = resolve_prompt_input(prompt, options.get("analyze_roles"))
            self._blocked.append(_truncate_for_history(text))
        return result

    def analyze(self, prompt: PromptInput, **options: Unpack[AnalyzeOptions]) -> AnalysisResult:
        """Analyze ``prompt`` with the session defaults, escalate a deferred reference and record a block."""
        return self._analyze(prompt, {**self._defaults, **options})

    def verify(self, prompt: PromptInput, **options: Unpack[AnalyzeOptions]) -> None:
        """Raise ``PromptInjectionError`` when the session blocks ``prompt``."""
        result = self.analyze(prompt, **options)
        if result.action == "block":
            raise PromptInjectionError(score=result.score, matches=result.matches, categories=result.categories)

    def strip(self, prompt: PromptInput, **options: Unpack[StripOptions]) -> str:
        """Record a block as ``analyze`` does, then return ``strip_prompt`` of the current prompt alone."""
        merged = {**self._defaults, **options}
        self._analyze(prompt, merged)
        return strip_prompt(prompt, **merged)

    def clear(self) -> None:
        """Forget every blocked prompt, which stops correlation."""
        self._blocked.clear()

    def get_blocked_history(self) -> list[str]:
        """Return a copy of the recorded blocked prompts, oldest first."""
        return list(self._blocked)


def create_protection_session(
    *,
    max_blocked_history: int = DEFAULT_MAX_BLOCKED_HISTORY,
    correlate_blocked: bool = True,
    **analyze_options: Unpack[AnalyzeOptions],
) -> ProtectionSession:
    """Create a session that escalates a deferred-reference follow-up after a blocked prompt.

    Raises ``ValueError`` for a negative ``max_blocked_history``. An ``ml`` other than ``off`` raises
    ``DeferredFeatureError`` from the first ``analyze``, ``verify`` or ``strip`` call that uses it.
    """
    return ProtectionSession(
        max_blocked_history=max_blocked_history, correlate_blocked=correlate_blocked, defaults=analyze_options
    )
