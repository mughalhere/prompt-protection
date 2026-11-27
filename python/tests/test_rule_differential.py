"""Rule differential: Python rule spans equal the JS golden spans."""

from typing import Any

from prompt_protection._rules import RULES, match_spans

SEPARATOR_CASE_COUNT = 168


def python_spans(text: str) -> list[tuple[str, int, int]]:
    return sorted((rule.id, start, end) for rule in RULES for start, end in match_spans(rule.pattern, text))


def golden_spans(matches: list[list[Any]]) -> list[tuple[str, int, int]]:
    return sorted((rule_id, start, end) for rule_id, start, end in matches)


def case_mismatches(case: dict[str, Any]) -> dict[str, Any]:
    pairs = {"raw": case["text"], "normalized": case["normalized"]}
    found = {form: python_spans(text) for form, text in pairs.items()}
    wanted = {form: golden_spans(case["ruleMatches"][form]) for form in pairs}
    return {form: {"python": found[form], "js": wanted[form]} for form in pairs if found[form] != wanted[form]}


def test_python_spans_equal_js_spans_for_the_golden_case(golden_case: dict[str, Any]) -> None:
    assert case_mismatches(golden_case) == {}


def test_python_spans_equal_js_spans_for_all_168_separator_cases(golden: dict[str, Any]) -> None:
    cases = [(i, case) for i, case in enumerate(golden["cases"]) if case["origin"] == "separator"]
    assert len(cases) == SEPARATOR_CASE_COUNT
    assert {i: mismatch for i, case in cases if (mismatch := case_mismatches(case))} == {}


def test_golden_holds_rule_matches_so_the_differential_is_not_vacuous(golden: dict[str, Any]) -> None:
    separator_cases = [case for case in golden["cases"] if case["origin"] == "separator"]
    assert sum(len(case["ruleMatches"]["raw"]) for case in golden["cases"]) > 0
    assert sum(len(case["ruleMatches"]["normalized"]) for case in separator_cases) > 0
