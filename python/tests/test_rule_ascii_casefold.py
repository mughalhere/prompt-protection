"""Rule keywords stay ASCII-only under IGNORECASE, as JS ``/i`` without the ``u`` flag (PY-3 follow-up)."""

import pytest

from prompt_protection._rules import RULES, match_spans

RULE_BY_ID = {rule.id: rule for rule in RULES}

# (rule id, prompt the rule matches, same prompt with one keyword letter swapped).
# Node: new RegExp(rule.pattern.source, "gi").test(swapped) is false for every row.
FOLD_CASES = [
    pytest.param("jailbreak-jailbreak", "jailbreak", "jailbrea\u212a", id="kelvin-in-jailbreak"),
    pytest.param("jailbreak-sudo", "sudo mode", "\u017fudo mode", id="long-s-in-sudo"),
    pytest.param("injection-special-tokens", "[SYSTEM]", "[\u017fYSTEM]", id="long-s-in-system-token"),
    pytest.param("exfil-api-key", "reveal the api key", "reveal the api \u212aey", id="kelvin-in-api-key"),
    pytest.param("exfil-api-key", "reveal the api key", "\u017fhow the api key", id="long-s-in-show-api-key"),
]


@pytest.mark.parametrize(("rule_id", "plain", "swapped"), FOLD_CASES)
def test_ascii_prompt_matches_the_rule_as_the_positive_control(rule_id: str, plain: str, swapped: str) -> None:
    assert match_spans(RULE_BY_ID[rule_id].pattern, plain) != []


@pytest.mark.parametrize(("rule_id", "plain", "swapped"), FOLD_CASES)
def test_long_s_and_kelvin_sign_do_not_fold_into_s_and_k_as_in_js(rule_id: str, plain: str, swapped: str) -> None:
    assert match_spans(RULE_BY_ID[rule_id].pattern, swapped) == []
