"""RED tests for prompt_protection.verdict.

Expected values come from Node 22 running the bundled precisionAllowsBlock() and resolveAction() of
src/verdict.ts (dist/internal.js). A match is any object with rule.precision and rule.category.
"""

from types import SimpleNamespace
from typing import Any

import pytest

from prompt_protection.verdict import precision_allows_block, resolve_action


def match(precision: str, category: str = "a") -> Any:
    return SimpleNamespace(rule=SimpleNamespace(precision=precision, category=category))


LOW_A = [match("low", "a")]
LOW_AB = [match("low", "a"), match("low", "b")]
HIGH_A = [match("high", "a")]

PRECISION_CASES = [
    pytest.param([], False, id="empty-never-blocks"),
    pytest.param(LOW_A, False, id="lone-low-never-blocks"),
    pytest.param([match("low"), match("low"), match("low")], False, id="three-lows-of-one-category"),
    pytest.param(LOW_AB, True, id="two-categories-of-low-block"),
    pytest.param([match("low", "a"), match("low", "b"), match("low", "c")], True, id="three-categories-of-low-block"),
    pytest.param([match("low", "a"), match("medium", "a")], True, id="low-plus-medium-blocks"),
    pytest.param([match("low", "a"), match("high", "b")], True, id="low-plus-high-blocks"),
    pytest.param([match("medium")], True, id="lone-medium-blocks"),
    pytest.param(HIGH_A, True, id="lone-high-blocks"),
]

# (score, matches, threshold, flag_threshold or no argument, action)
ACTION_CASES = [
    pytest.param(50, HIGH_A, 50, (), "block", id="score-at-threshold-blocks"),
    pytest.param(49, HIGH_A, 50, (), "allow", id="below-threshold-allows"),
    pytest.param(50, LOW_A, 50, (), "flag", id="lone-low-at-threshold-flags-not-blocks"),
    pytest.param(80, LOW_A, 50, (), "flag", id="lone-low-above-threshold-flags"),
    pytest.param(80, LOW_AB, 50, (), "block", id="two-low-categories-block"),
    pytest.param(80, [], 50, (), "block", id="empty-matches-above-threshold-block"),
    pytest.param(0, [], 0, (), "block", id="empty-matches-threshold-zero-block"),
    pytest.param(0, [], 50, (), "allow", id="empty-matches-below-threshold-allow"),
    pytest.param(0, LOW_A, 0, (), "flag", id="threshold-zero-lone-low-flags"),
    pytest.param(0, HIGH_A, 0, (), "block", id="threshold-zero-high-blocks"),
    pytest.param(100, [], 101, (), "allow", id="threshold-above-100-allows"),
    pytest.param(49, LOW_A, 50, (30,), "flag", id="flag-band-lone-low"),
    pytest.param(30, LOW_A, 50, (30,), "flag", id="score-at-flag-threshold-flags"),
    pytest.param(29, LOW_A, 50, (30,), "allow", id="below-flag-threshold-allows"),
    pytest.param(49, HIGH_A, 50, (30,), "flag", id="flag-band-high"),
    pytest.param(29, [], 50, (30,), "allow", id="below-flag-band-empty-allows"),
    pytest.param(0, [], 50, (0,), "flag", id="flag-threshold-zero-is-set-not-omitted"),
    pytest.param(10, HIGH_A, 50, (0,), "flag", id="flag-threshold-zero-flags-any-score"),
    pytest.param(60, HIGH_A, 50, (70,), "block", id="flag-threshold-above-threshold-block-wins"),
    pytest.param(60, LOW_A, 50, (70,), "flag", id="flag-threshold-above-threshold-low-flags"),
    pytest.param(50, [], 50, (50,), "block", id="both-thresholds-equal-block-wins"),
    pytest.param(40, HIGH_A, 50, (None,), "allow", id="flag-threshold-none-is-omitted"),
]


@pytest.mark.parametrize(("matches", "expected"), PRECISION_CASES)
def test_precision_allows_block_matches_node(matches: list[Any], expected: bool) -> None:
    assert precision_allows_block(matches) is expected


@pytest.mark.parametrize(("value", "matches", "threshold", "flag", "action"), ACTION_CASES)
def test_resolve_action_matches_node(
    value: int, matches: list[Any], threshold: int, flag: tuple[Any, ...], action: str
) -> None:
    assert resolve_action(value, matches, threshold, *flag) == action
