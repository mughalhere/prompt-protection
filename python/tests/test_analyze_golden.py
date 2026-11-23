"""RED golden test for prompt_protection.analyze_prompt (PY-7; plan design item 5, owner decision 5).

tests/__fixtures__/analyze.golden.json holds what the JS analyzePrompt returned on Node 22 for every case.
The Python result is compared through to_dict(), so the JS camelCase keys are what the golden checks.
"""

from typing import Any

from prompt_protection import analyze_prompt

PROJECTED_KEYS = ("score", "severity", "action", "categories")


def project(result: dict[str, Any]) -> dict[str, Any]:
    projected = {key: result[key] for key in PROJECTED_KEYS}
    projected["ruleIds"] = [hit["rule"]["id"] for hit in result["matches"]]
    return projected


def test_the_golden_holds_cases_so_the_comparison_is_not_vacuous(golden: dict[str, Any]) -> None:
    assert len(golden["cases"]) > 1000


def test_to_dict_projection_equals_the_js_golden_for_the_case(golden_case: dict[str, Any], deadline: None) -> None:
    wanted = {key: golden_case[key] for key in (*PROJECTED_KEYS, "ruleIds")}
    assert project(analyze_prompt(golden_case["text"]).to_dict()) == wanted


def test_normalized_prompt_equals_the_js_golden_for_the_case(golden_case: dict[str, Any], deadline: None) -> None:
    assert analyze_prompt(golden_case["text"]).to_dict()["normalizedPrompt"] == golden_case["normalized"]
