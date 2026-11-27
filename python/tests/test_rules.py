"""RED tests for prompt_protection._rules (expected spans come from Node 22)."""

import re
from typing import Any

import pytest

import prompt_protection
from prompt_protection._rules import DEFERRED_REFERENCE_RULE_IDS, RULES, RULES_VERSION, match_spans

RULE_FIELDS = ("id", "source", "weight", "category", "precision")

# Oracle: Node 22 exec loop over new RegExp(source, 'gi'), lastIndex++ after an empty match (src/scorer.ts).
EXEC_LOOP_CASES = [
    pytest.param("x*", "", [(0, 0)], id="empty-text"),
    pytest.param("a", "bbb", [], id="no-match"),
    pytest.param("a*", "baab", [(0, 0), (1, 3), (3, 3), (4, 4)], id="empty-then-nonempty-then-empty"),
    pytest.param("b", "\U0001f600b", [(2, 3)], id="non-empty-after-astral"),
    pytest.param("x*", "\U0001f600", [(0, 0), (1, 1), (2, 2)], id="astral-empty-match"),
    pytest.param("x*", "a\U0001f600b", [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)], id="astral-embedded-empty-match"),
    pytest.param("x*", "\U0001f600\U0001f600", [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)], id="two-astral-empty-match"),
    pytest.param(r"\w*", "\U0001f600ab", [(0, 0), (1, 1), (2, 4), (4, 4)], id="astral-then-nonempty"),
    pytest.param("a|", "\U0001f600a", [(0, 0), (1, 1), (2, 3), (3, 3)], id="alternation-with-empty-branch"),
]


def test_exactly_107_rules() -> None:
    assert len(RULES) == 107


def test_rule_ids_are_unique() -> None:
    ids = [rule.id for rule in RULES]
    assert len(set(ids)) == len(ids)


def test_rules_carry_the_exported_fields_in_exported_order(rules_json: dict[str, Any]) -> None:
    loaded = [tuple(getattr(rule, field) for field in RULE_FIELDS) for rule in RULES]
    exported = [tuple(entry[field] for field in RULE_FIELDS) for entry in rules_json["rules"]]
    assert loaded == exported


def test_every_rule_compiles_its_source_with_ascii_and_ignorecase() -> None:
    wrong = [
        rule.id
        for rule in RULES
        if rule.pattern.flags != re.ASCII | re.IGNORECASE or rule.pattern.pattern != rule.source
    ]
    assert wrong == []


def test_rules_version_equals_rules_digest_version(rules_digest: dict[str, str]) -> None:
    assert RULES_VERSION == rules_digest["rulesVersion"]


def test_package_reexports_rules_version() -> None:
    assert prompt_protection.RULES_VERSION == RULES_VERSION


def test_deferred_reference_rule_ids_equal_rules_json(rules_json: dict[str, Any]) -> None:
    assert sorted(DEFERRED_REFERENCE_RULE_IDS) == sorted(rules_json["deferredReferenceRuleIds"])
    assert len(DEFERRED_REFERENCE_RULE_IDS) == 3


@pytest.mark.usefixtures("deadline")
@pytest.mark.parametrize(("source", "text", "expected"), EXEC_LOOP_CASES)
def test_match_spans_equals_the_js_exec_loop_in_utf16_offsets(
    source: str, text: str, expected: list[tuple[int, int]]
) -> None:
    spans = match_spans(re.compile(source, re.ASCII | re.IGNORECASE), text)
    assert [tuple(span) for span in spans] == expected
