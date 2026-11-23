"""Block, flag or allow from a score and its matches, ported from src/verdict.ts."""

from collections.abc import Sequence
from typing import Literal

from prompt_protection.scorer import PatternMatch

__all__ = ["Action", "precision_allows_block", "resolve_action"]

Action = Literal["allow", "flag", "block"]


def precision_allows_block(matches: Sequence[PatternMatch]) -> bool:
    """Return whether the matches may block: one non-low precision match, or two threat categories."""
    if not matches:
        return False
    if any(hit.rule.precision != "low" for hit in matches):
        return True
    return len({hit.rule.category for hit in matches}) >= 2


def resolve_action(
    score: float, matches: Sequence[PatternMatch], threshold: float, flag_threshold: float | None = None
) -> Action:
    """Return ``block`` at ``score >= threshold``, ``flag`` in the flag band, else ``allow``.

    A would-be block with only low-precision matches in one category becomes ``flag``.
    Empty matches keep the block, so a threshold of 0 blocks everything.
    """
    if score >= threshold:
        return "block" if not matches or precision_allows_block(matches) else "flag"
    if flag_threshold is not None and score >= flag_threshold:
        return "flag"
    return "allow"
