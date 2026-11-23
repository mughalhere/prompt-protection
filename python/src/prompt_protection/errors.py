"""Exceptions of the public API (twin of src/error.ts)."""

from collections.abc import Sequence

from prompt_protection._js import js_number_str
from prompt_protection.scorer import PatternMatch

__all__ = ["DeferredFeatureError", "PromptInjectionError"]


class DeferredFeatureError(ValueError):
    """Raised for an option the JS package has and the Python package does not support yet."""


class PromptInjectionError(Exception):
    """Raised when a prompt is judged malicious; carries the score, the matches and the categories."""

    def __init__(self, *, score: float, matches: Sequence[PatternMatch], categories: Sequence[str]) -> None:
        listed = ", ".join(categories)
        super().__init__(f"Potentially malicious prompt detected (score: {js_number_str(score)}, categories: {listed})")
        self.score = score
        self.matches = matches
        self.categories = categories
