"""Empty-match termination of score() (PY-6 follow-up, bead wtw).

Expected values come from Node 22 running the score() of dist/internal.js, or a manual lastIndex++ loop
over the same body where the bundle would hang (a custom x* rule). Python advances one UTF-16 unit.
"""

import re
from typing import Any

import pytest

from prompt_protection._rules import Rule
from prompt_protection.scorer import score

NONE = (0, 0, [])
X = ("x", "x*", 4)
A = ("a", "a*", 10)


def rule(spec: tuple[str, str, int]) -> Rule:
    rule_id, pattern, weight = spec
    return Rule(
        id=rule_id,
        source=pattern,
        weight=weight,
        category="prompt-injection",
        precision="medium",
        pattern=re.compile(pattern, re.IGNORECASE),
    )


def summary(result: Any) -> tuple[float, int, list[tuple[str, str, int, int]]]:
    hits = [(m.rule.id, m.matched_text, m.start_index, m.end_index) for m in result.matches]
    return result.raw_score, result.normalized_score, hits


EMPTY_RULE_CASES = [
    pytest.param(
        [X], "hello", (9, 45, [("x", c, i, i + 1) for i, c in enumerate("hello")] + [("x", "o", 4, 5)]), id="ascii"
    ),
    pytest.param([X], "", (4, 23, [("x", "", 0, 0)]), id="empty-text"),
    pytest.param(
        [X],
        "a\U0001f600b",
        (8, 41, [("x", "a", 0, 1), ("x", "\ud83d", 1, 2), ("x", "\ude00", 2, 3), ("x", "b", 3, 4), ("x", "b", 3, 4)]),
        id="astral-between-ascii",
    ),
    pytest.param(
        [X],
        "\U0001f600",
        (6, 33, [("x", "\ud83d", 0, 1), ("x", "\ude00", 1, 2), ("x", "\ude00", 1, 2)]),
        id="astral-only",
    ),
    pytest.param(
        [X],
        "xxhxx",
        (7, 37, [("x", "xx", 0, 2), ("x", "h", 2, 3), ("x", "xx", 3, 5), ("x", "x", 4, 5)]),
        id="empty-between-nonempty",
    ),
    pytest.param(
        [A, X],
        "baab",
        (
            25.5,
            82,
            [("a", "b", 0, 1), ("a", "aa", 1, 3), ("a", "b", 3, 4), ("a", "b", 3, 4)]
            + [("x", "b", 0, 1), ("x", "a", 1, 2), ("x", "a", 2, 3), ("x", "b", 3, 4), ("x", "b", 3, 4)],
        ),
        id="two-empty-matching-rules",
    ),
]


@pytest.mark.parametrize(("specs", "text", "expected"), EMPTY_RULE_CASES)
def test_empty_matching_rule_terminates_with_the_node_manual_loop_spans(
    specs: list[tuple[str, str, int]], text: str, expected: Any, deadline: None
) -> None:
    assert summary(score([rule(s) for s in specs], text, text)) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("hello", NONE, id="empty-spans-inside-the-hit-allowlist-it"),
        pytest.param("a\U0001f600lb", (4, 23, [("r", "l", 3, 4)]), id="astral-before-the-hit-leaves-it"),
    ],
)
def test_allowlist_pattern_matching_empty_terminates_like_node(text: str, expected: Any, deadline: None) -> None:
    result = score([rule(("r", "l+", 4))], text, text, allowlist_patterns=[re.compile("x*", re.IGNORECASE)])
    assert summary(result) == expected


def test_allowlisted_empty_matching_rule_id_is_skipped_without_looping(deadline: None) -> None:
    result = score([rule(X)], "hello", "hello", allowlist_rule_ids=["x"])
    assert summary(result) == NONE
