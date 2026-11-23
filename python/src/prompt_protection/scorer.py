"""Rule scoring ported from src/scorer.ts: weighted matches, diminishing returns and allowlists."""

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass

from prompt_protection._js import js_round, utf16_len, utf16_slice
from prompt_protection._rules import Rule, match_spans

__all__ = ["PatternMatch", "ScoreResult", "score"]

_REPEAT_WEIGHT = 0.25
_SCORE_SCALE = 15


@dataclass(frozen=True, slots=True)
class PatternMatch:
    rule: Rule
    matched_text: str
    start_index: int
    end_index: int


@dataclass(frozen=True, slots=True)
class ScoreResult:
    raw_score: float
    normalized_score: int
    matches: list[PatternMatch]


def _exp(value: float) -> float:
    """Return ``Math.exp(value)``: an overflow is infinity, as in JS, not an ``OverflowError``."""
    try:
        return math.exp(value)
    except OverflowError:
        return math.inf


def _as_double(weight: int) -> float:
    """Return ``weight`` as an IEEE double; an int beyond double range is a signed infinity, as in JS."""
    try:
        return float(weight)
    except OverflowError:
        return math.inf if weight > 0 else -math.inf


def _normalize_score(raw_score: float) -> int:
    scaled = 100 * (1 - _exp(-raw_score / _SCORE_SCALE))
    if not math.isfinite(scaled):
        raise ValueError(f"score must be finite before rounding, got {scaled!r} from raw score {raw_score!r}")
    return js_round(scaled)


def _map_index(index_map: Sequence[int] | None, normalized_index: int, fallback_length: int) -> int:
    if index_map:
        return index_map[min(normalized_index, len(index_map) - 1)]
    return min(normalized_index, max(fallback_length - 1, 0))


def _overlaps_allowlist(span: tuple[int, int], allowlist_spans: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(start < allowed_end and allowed_start < end for allowed_start, allowed_end in allowlist_spans)


def score(
    rules: Sequence[Rule],
    normalized_text: str,
    original_text: str,
    *,
    index_map: Sequence[int] | None = None,
    allowlist_patterns: Sequence[re.Pattern[str]] | None = None,
    allowlist_rule_ids: Sequence[str] | None = None,
) -> ScoreResult:
    """Run every rule over ``normalized_text`` and sum the weights, a repeat of one rule id counting a quarter.

    Match offsets are UTF-16 units of ``original_text``, mapped through ``index_map`` when it is given.
    Spans that overlap an allowlist pattern, and rules named in ``allowlist_rule_ids``, are skipped.
    Raises ``ValueError`` when the score is not finite before rounding.
    """
    allowlist_spans = [span for pattern in allowlist_patterns or () for span in match_spans(pattern, normalized_text)]
    skipped_ids = set(allowlist_rule_ids or ())
    original_length = utf16_len(original_text)
    matches: list[PatternMatch] = []

    for rule in rules:
        if rule.id in skipped_ids:
            continue
        for start, end in match_spans(rule.pattern, normalized_text):
            if _overlaps_allowlist((start, end), allowlist_spans):
                continue
            start_index = _map_index(index_map, start, original_length)
            mapped_end = _map_index(index_map, max(end - 1, start), original_length)
            end_index = min(mapped_end + 1, original_length)
            matches.append(
                PatternMatch(rule, utf16_slice(original_text, start_index, end_index), start_index, end_index)
            )

    raw_score = 0.0
    seen: set[str] = set()
    for hit in matches:
        weight = _as_double(hit.rule.weight)
        raw_score += weight * _REPEAT_WEIGHT if hit.rule.id in seen else weight
        seen.add(hit.rule.id)

    return ScoreResult(raw_score, _normalize_score(raw_score), matches)
