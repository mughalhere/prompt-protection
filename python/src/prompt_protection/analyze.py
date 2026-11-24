"""Prompt analysis and stripping, ported from src/core/analyze.ts and the two public functions of src/api.ts."""

import re
from collections.abc import Sequence
from dataclasses import dataclass

from prompt_protection._js import JS_WHITESPACE, code_units, js_trim, utf16_len, utf16_slice
from prompt_protection._result import JsResult
from prompt_protection._rules import _FLAGS, RULES, Rule
from prompt_protection._types import AnalyzeRoles, CustomRule, FailMode, MlMode, PromptInput, Severity
from prompt_protection.errors import DeferredFeatureError, PromptInjectionError
from prompt_protection.messages import resolve_prompt_input
from prompt_protection.normalizer import normalize
from prompt_protection.scorer import PatternMatch, score
from prompt_protection.verdict import Action, resolve_action

__all__ = [
    "DEFAULT_MAX_INPUT_LENGTH",
    "DEFAULT_THRESHOLD",
    "INTERNAL_ERROR_RULE",
    "AnalysisError",
    "AnalysisResult",
    "SentenceScore",
    "analyze_prompt",
    "build_rule_set",
    "cap_length",
    "compute_severity",
    "failed_analysis",
    "strip_prompt",
    "verify_prompt",
]

DEFAULT_THRESHOLD = 35
DEFAULT_MAX_INPUT_LENGTH = 100_000
_SENTENCE_SPLIT = re.compile(f"[.!?]+{JS_WHITESPACE}+")
_SEGMENT_END = frozenset(map(ord, ".\n!?"))

INTERNAL_ERROR_RULE = Rule(
    id="internal-error",
    source="(?!)",
    weight=10,
    category="prompt-injection",
    precision="high",
    pattern=re.compile("(?!)", _FLAGS),
    description="Analysis failed internally; verdict decided by failMode",
)


@dataclass(frozen=True, slots=True)
class AnalysisError(JsResult):
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class SentenceScore(JsResult):
    sentence: str
    score: int


@dataclass(frozen=True, slots=True)
class AnalysisResult(JsResult):
    score: float
    severity: Severity
    is_malicious: bool
    action: Action
    matches: list[PatternMatch]
    categories: list[str]
    normalized_prompt: str
    sentence_scores: list[SentenceScore] | None = None
    error: AnalysisError | None = None


def cap_length(text: str, max_input_length: int | None) -> str:
    """Cut ``text`` to ``max_input_length`` UTF-16 units; ``None`` means the default cap."""
    cap = DEFAULT_MAX_INPUT_LENGTH if max_input_length is None else max_input_length
    return utf16_slice(text, 0, cap) if utf16_len(text) > cap else text


def compute_severity(value: float) -> Severity:
    if value >= 80:
        return "critical"
    if value >= 65:
        return "high"
    if value >= 50:
        return "medium"
    if value >= 25:
        return "low"
    return "safe"


def _split_sentences(text: str) -> list[str]:
    return [s for s in (js_trim(part) for part in _SENTENCE_SPLIT.split(text)) if utf16_len(s) > 3]


def _custom_rule(spec: CustomRule) -> Rule:
    source = spec["pattern"].pattern
    return Rule(
        id=spec["id"],
        source=source,
        weight=spec["weight"],  # type: ignore[arg-type]
        category=spec["category"],
        precision=spec.get("precision", "medium"),
        pattern=re.compile(source, _FLAGS),
        description=spec["description"],
    )


def build_rule_set(
    *,
    disabled_categories: Sequence[str] | None = None,
    disabled_rule_ids: Sequence[str] | None = None,
    custom_rules: Sequence[CustomRule] | None = None,
) -> list[Rule]:
    """Filter the built-in rules by category and id, then append the custom rules."""
    rules = list(RULES)
    if disabled_categories:
        rules = [rule for rule in rules if rule.category not in set(disabled_categories)]
    if disabled_rule_ids:
        rules = [rule for rule in rules if rule.id not in set(disabled_rule_ids)]
    if custom_rules:
        rules.extend(_custom_rule(spec) for spec in custom_rules)
    return rules


def failed_analysis(error: Exception, fail_mode: FailMode, threshold: float) -> AnalysisResult:
    """Return the verdict for an internal failure: block when closed, allow when open."""
    detail = AnalysisError(code="internal-error", message=str(error))
    if fail_mode == "open":
        return AnalysisResult(0, "safe", False, "allow", [], [], "", error=detail)
    hit = PatternMatch(INTERNAL_ERROR_RULE, "", 0, 0)
    return AnalysisResult(threshold, compute_severity(threshold), True, "block", [hit], [], "", error=detail)


def _check_ml(ml: MlMode | None) -> None:
    if ml not in (None, "off"):
        raise DeferredFeatureError(f"prompt-protection: ml={ml!r} is not supported in the Python package; use ml='off'")


def analyze_prompt(
    prompt: PromptInput,
    *,
    threshold: float = DEFAULT_THRESHOLD,
    flag_threshold: float | None = None,
    custom_rules: Sequence[CustomRule] | None = None,
    disabled_categories: Sequence[str] | None = None,
    disabled_rule_ids: Sequence[str] | None = None,
    allowlist_patterns: Sequence[re.Pattern[str]] | None = None,
    allowlist_rule_ids: Sequence[str] | None = None,
    sentence_analysis: bool = False,
    analyze_roles: AnalyzeRoles | None = None,
    max_input_length: int | None = None,
    ml: MlMode | None = None,
    fail_mode: FailMode = "closed",
) -> AnalysisResult:
    """Score a prompt against the rules. An internal failure returns the ``fail_mode`` verdict.

    Raises ``DeferredFeatureError`` for any ``ml`` other than ``off``, whatever ``fail_mode`` says.
    """
    _check_ml(ml)
    try:
        rules = build_rule_set(
            disabled_categories=disabled_categories, disabled_rule_ids=disabled_rule_ids, custom_rules=custom_rules
        )
        text = cap_length(resolve_prompt_input(prompt, analyze_roles), max_input_length)
        normalized = normalize(text)
        scored = score(
            rules,
            normalized.normalized,
            text,
            index_map=normalized.index_map,
            allowlist_patterns=allowlist_patterns,
            allowlist_rule_ids=allowlist_rule_ids,
        )
        action = resolve_action(scored.normalized_score, scored.matches, threshold, flag_threshold)
        sentence_scores = None
        if sentence_analysis:
            sentence_scores = [
                SentenceScore(sentence, _sentence_score(rules, sentence, allowlist_patterns, allowlist_rule_ids))
                for sentence in _split_sentences(text)
            ]
        return AnalysisResult(
            score=scored.normalized_score,
            severity=compute_severity(scored.normalized_score),
            is_malicious=action == "block",
            action=action,
            matches=scored.matches,
            categories=list(dict.fromkeys(hit.rule.category for hit in scored.matches)),
            normalized_prompt=normalized.normalized,
            sentence_scores=sentence_scores,
        )
    except Exception as error:
        return failed_analysis(error, fail_mode, threshold)


def verify_prompt(
    prompt: PromptInput,
    *,
    threshold: float = DEFAULT_THRESHOLD,
    flag_threshold: float | None = None,
    custom_rules: Sequence[CustomRule] | None = None,
    disabled_categories: Sequence[str] | None = None,
    disabled_rule_ids: Sequence[str] | None = None,
    allowlist_patterns: Sequence[re.Pattern[str]] | None = None,
    allowlist_rule_ids: Sequence[str] | None = None,
    sentence_analysis: bool = False,
    analyze_roles: AnalyzeRoles | None = None,
    max_input_length: int | None = None,
    ml: MlMode | None = None,
    fail_mode: FailMode = "closed",
) -> None:
    """Raise ``PromptInjectionError`` when ``analyze_prompt`` blocks ``prompt``; return ``None`` otherwise.

    Raises ``DeferredFeatureError`` for any ``ml`` other than ``off``, whatever ``fail_mode`` says.
    """
    result = analyze_prompt(
        prompt,
        threshold=threshold,
        flag_threshold=flag_threshold,
        custom_rules=custom_rules,
        disabled_categories=disabled_categories,
        disabled_rule_ids=disabled_rule_ids,
        allowlist_patterns=allowlist_patterns,
        allowlist_rule_ids=allowlist_rule_ids,
        sentence_analysis=sentence_analysis,
        analyze_roles=analyze_roles,
        max_input_length=max_input_length,
        ml=ml,
        fail_mode=fail_mode,
    )
    if result.action == "block":
        raise PromptInjectionError(score=result.score, matches=result.matches, categories=result.categories)


def _sentence_score(
    rules: Sequence[Rule],
    sentence: str,
    allowlist_patterns: Sequence[re.Pattern[str]] | None,
    allowlist_rule_ids: Sequence[str] | None,
) -> int:
    normalized = normalize(sentence)
    return score(
        rules,
        normalized.normalized,
        sentence,
        index_map=normalized.index_map,
        allowlist_patterns=allowlist_patterns,
        allowlist_rule_ids=allowlist_rule_ids,
    ).normalized_score


def _merge_spans(matches: Sequence[PatternMatch]) -> list[list[int]]:
    merged: list[list[int]] = []
    for start, end in sorted((hit.start_index, hit.end_index) for hit in matches):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _widen_to_segments(spans: list[list[int]], units: list[int]) -> None:
    for span in spans:
        start, end = span
        while start > 0 and units[start - 1] not in _SEGMENT_END:
            start -= 1
        while end < len(units) and units[end] not in _SEGMENT_END:
            end += 1
        span[0], span[1] = start, end + 1 if end < len(units) else end


def strip_prompt(
    prompt: PromptInput,
    *,
    replacement: str = "",
    strip_whole_segment: bool = False,
    threshold: float = DEFAULT_THRESHOLD,
    flag_threshold: float | None = None,
    custom_rules: Sequence[CustomRule] | None = None,
    disabled_categories: Sequence[str] | None = None,
    disabled_rule_ids: Sequence[str] | None = None,
    allowlist_patterns: Sequence[re.Pattern[str]] | None = None,
    allowlist_rule_ids: Sequence[str] | None = None,
    sentence_analysis: bool = False,
    analyze_roles: AnalyzeRoles | None = None,
    max_input_length: int | None = None,
    ml: MlMode | None = None,
    fail_mode: FailMode = "closed",
) -> str:
    """Splice every matched span out of the prompt text and trim the result with the JS whitespace set.

    Raises ``TypeError`` on a bad input and ``DeferredFeatureError`` for any ``ml`` other than ``off``.
    """
    _check_ml(ml)
    text = resolve_prompt_input(prompt, analyze_roles)
    result = analyze_prompt(
        text,
        threshold=threshold,
        flag_threshold=flag_threshold,
        custom_rules=custom_rules,
        disabled_categories=disabled_categories,
        disabled_rule_ids=disabled_rule_ids,
        allowlist_patterns=allowlist_patterns,
        allowlist_rule_ids=allowlist_rule_ids,
        sentence_analysis=sentence_analysis,
        max_input_length=max_input_length,
        fail_mode=fail_mode,
    )
    if not result.matches:
        return text
    spans = _merge_spans(result.matches)
    units = code_units(text)
    if strip_whole_segment:
        _widen_to_segments(spans, units)
    stripped = text
    for start, end in reversed(spans):
        stripped = utf16_slice(stripped, 0, start) + replacement + utf16_slice(stripped, end)
    return js_trim(stripped)
