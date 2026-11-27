"""Direct tests for four helpers that other suites reach only through larger calls.

Twins: ``buildRuleSet`` and ``capLength`` in src/core/analyze.ts, ``decodeURIComponent`` as src/utils/encoding.ts
uses it (``decode_run`` is the nested run decoder of ``decode_uri_component``), and ``denial`` in
src/adapters/protect-core.ts. Expected counts and decoded strings come from Node 22 on the built package.
"""

import re
from types import SimpleNamespace
from typing import Any

import pytest

from prompt_protection._js import decode_uri_component
from prompt_protection._rules import RULES
from prompt_protection.adapters._core import Denial, denial
from prompt_protection.analyze import DEFAULT_MAX_INPUT_LENGTH, build_rule_set, cap_length

TOTAL_RULES = 107
FIRST_RULE = "injection-ignore-previous"
LAST_RULE = "tool-ignore-previous"
JAILBREAK_RULE = "jailbreak-dan"


def make_custom(**overrides: Any) -> dict[str, Any]:
    return {
        "id": "custom-zz",
        "category": "prompt-injection",
        "pattern": re.compile("zzqq"),
        "weight": 5,
        "description": "custom test rule",
        **overrides,
    }


def ids_of(rules: list[Any]) -> list[str]:
    return [rule.id for rule in rules]


@pytest.mark.parametrize(
    ("kwargs", "expected_count"),
    [
        pytest.param({}, TOTAL_RULES, id="no-options-keeps-all"),
        pytest.param(
            {"disabled_categories": [], "disabled_rule_ids": [], "custom_rules": []}, TOTAL_RULES, id="empty-lists"
        ),
        pytest.param({"disabled_categories": ["prompt-injection"]}, TOTAL_RULES - 25, id="one-category"),
        pytest.param(
            {"disabled_categories": ["jailbreak", "tool-poisoning", "no-such-category"]},
            TOTAL_RULES - 19 - 9,
            id="two-categories-and-an-unknown",
        ),
        pytest.param({"disabled_rule_ids": [FIRST_RULE]}, TOTAL_RULES - 1, id="one-rule-id"),
        pytest.param({"disabled_rule_ids": [FIRST_RULE, "no-such-rule"]}, TOTAL_RULES - 1, id="rule-id-and-unknown"),
        pytest.param({"disabled_rule_ids": ["no-such-rule"]}, TOTAL_RULES, id="unknown-rule-id-only"),
        pytest.param(
            {"disabled_categories": ["prompt-injection"], "disabled_rule_ids": [JAILBREAK_RULE]},
            TOTAL_RULES - 25 - 1,
            id="category-and-id-both-apply",
        ),
    ],
)
def test_build_rule_set_counts(kwargs: dict[str, Any], expected_count: int) -> None:
    assert len(build_rule_set(**kwargs)) == expected_count


def test_build_rule_set_default_is_the_builtin_pack_in_order_and_a_fresh_list() -> None:
    rules = build_rule_set()
    assert ids_of(rules) == ids_of(list(RULES))
    assert rules[0].id == FIRST_RULE
    assert rules[-1].id == LAST_RULE
    rules.clear()
    assert len(build_rule_set()) == TOTAL_RULES


def test_build_rule_set_removes_exactly_the_named_category_and_keeps_order() -> None:
    kept = build_rule_set(disabled_categories=["prompt-injection"])
    assert all(rule.category != "prompt-injection" for rule in kept)
    assert ids_of(kept) == [rule.id for rule in RULES if rule.category != "prompt-injection"]


def test_build_rule_set_removes_exactly_the_named_id() -> None:
    kept = build_rule_set(disabled_rule_ids=[FIRST_RULE])
    assert FIRST_RULE not in ids_of(kept)
    assert ids_of(kept) == [rule.id for rule in RULES][1:]


def test_build_rule_set_appends_custom_rules_last_in_the_order_given() -> None:
    rules = build_rule_set(custom_rules=[make_custom(id="c-1"), make_custom(id="c-2")])
    assert len(rules) == TOTAL_RULES + 2
    assert ids_of(rules)[:TOTAL_RULES] == ids_of(list(RULES))
    assert ids_of(rules)[-2:] == ["c-1", "c-2"]
    assert len(RULES) == TOTAL_RULES


def test_build_rule_set_custom_rules_are_not_filtered_by_the_disabled_options() -> None:
    rules = build_rule_set(
        disabled_categories=["prompt-injection"], disabled_rule_ids=["custom-zz"], custom_rules=[make_custom()]
    )
    assert rules[-1].id == "custom-zz"
    assert rules[-1].category == "prompt-injection"
    assert len(rules) == TOTAL_RULES - 25 + 1


def test_build_rule_set_custom_rule_fields_and_defaults() -> None:
    rule = build_rule_set(custom_rules=[make_custom()])[-1]
    assert (rule.id, rule.category, rule.weight, rule.description) == (
        "custom-zz",
        "prompt-injection",
        5,
        "custom test rule",
    )
    assert rule.source == "zzqq"
    assert rule.precision == "medium"
    assert rule.mappings is None
    assert rule.origin is None
    assert rule.pattern.search("a ZZQQ b") is not None


def test_build_rule_set_custom_rule_carries_explicit_precision_mappings_and_origin() -> None:
    extra = {"precision": "low", "mappings": {"owasp": ["LLM01"]}, "origin": {"format": "sigma"}}
    rule = build_rule_set(custom_rules=[make_custom(**extra)])[-1]
    assert rule.precision == "low"
    assert rule.mappings == {"owasp": ["LLM01"]}
    assert rule.origin == {"format": "sigma"}


LONG_TEXT = "a" * (DEFAULT_MAX_INPUT_LENGTH + 1)
LONE_HIGH_SURROGATE = "\ud83d"
EMOJI = "\U0001f600"


@pytest.mark.parametrize(
    ("text", "limit", "expected"),
    [
        pytest.param("abc", 2, "ab", id="limit-shorter-than-text"),
        pytest.param("abc", 3, "abc", id="limit-equal-to-length"),
        pytest.param("abc", 4, "abc", id="limit-longer-than-text"),
        pytest.param("abc", 0, "", id="zero-limit-is-not-absent"),
        pytest.param("", 0, "", id="empty-text-zero-limit"),
        pytest.param("abc", -1, "ab", id="negative-limit-slices-from-the-end"),
        pytest.param("abc", -5, "", id="negative-limit-past-the-start"),
        pytest.param(EMOJI * 2, 2, EMOJI, id="limit-counts-utf16-units-not-code-points"),
        pytest.param(EMOJI * 3, 4, EMOJI * 2, id="four-units-keep-two-emoji"),
        pytest.param(EMOJI * 2, 4, EMOJI * 2, id="equal-in-units-keeps-all"),
        pytest.param(EMOJI * 2, 1, LONE_HIGH_SURROGATE, id="cut-inside-a-pair-leaves-a-lone-surrogate"),
        pytest.param(EMOJI * 2, 3, EMOJI + LONE_HIGH_SURROGATE, id="odd-limit-splits-the-second-pair"),
        pytest.param("é" + EMOJI, 1, "é", id="bmp-char-is-one-unit"),
    ],
)
def test_cap_length_cuts_to_utf16_units(text: str, limit: int, expected: str) -> None:
    assert cap_length(text, limit) == expected


@pytest.mark.parametrize(
    ("text", "expected_length"),
    [
        pytest.param(LONG_TEXT, DEFAULT_MAX_INPUT_LENGTH, id="over-default-is-cut"),
        pytest.param("a" * DEFAULT_MAX_INPUT_LENGTH, DEFAULT_MAX_INPUT_LENGTH, id="at-default-is-kept"),
        pytest.param("a" * (DEFAULT_MAX_INPUT_LENGTH - 1), DEFAULT_MAX_INPUT_LENGTH - 1, id="under-default-is-kept"),
    ],
)
def test_cap_length_none_limit_uses_the_default_cap(text: str, expected_length: int) -> None:
    assert DEFAULT_MAX_INPUT_LENGTH == 100_000
    assert len(cap_length(text, None)) == expected_length


def test_cap_length_returns_the_same_text_when_no_cut_is_needed() -> None:
    text = "unchanged " * 3
    assert cap_length(text, len(text)) is text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("%41", "A", id="decode_run-single-escape"),
        pytest.param("%e2%82%ac", "€", id="decode_run-lowercase-hex"),
        pytest.param("%E2%82%AC", "€", id="decode_run-three-byte-sequence"),
        pytest.param("%F0%9F%98%80", EMOJI, id="decode_run-four-byte-sequence"),
        pytest.param("%C3%A9%C3%A9", "éé", id="decode_run-two-sequences-in-one-run"),
        pytest.param("%E2%82%AC%E2%82%AC%41", "€€A", id="decode_run-mixed-widths-in-one-run"),
        pytest.param("a%41b%42c", "aAbBc", id="decode_run-separate-runs-between-literals"),
        pytest.param("%41 %C3%A9 x%42", "A é xB", id="decode_run-runs-split-by-spaces"),
        pytest.param("%2541", "%41", id="decode_run-decodes-once-only"),
        pytest.param("%2F%3F%23", "/?#", id="decode_run-reserved-characters-are-decoded"),
        pytest.param("%00", "\x00", id="decode_run-nul"),
        pytest.param("plain text", "plain text", id="no-escape-is-unchanged"),
        pytest.param("", "", id="empty-text"),
    ],
)
def test_decode_uri_component_decodes_percent_runs_like_js(text: str, expected: str) -> None:
    assert decode_uri_component(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("%E2%82", id="decode_run-truncated-three-byte-sequence"),
        pytest.param("%E2", id="decode_run-lone-lead-byte"),
        pytest.param("%80", id="decode_run-lone-continuation-byte"),
        pytest.param("%C0%80", id="decode_run-overlong-encoding"),
        pytest.param("%ED%A0%80", id="decode_run-encoded-surrogate"),
        pytest.param("%F4%90%80%80", id="decode_run-above-max-code-point"),
        pytest.param("%FF", id="decode_run-invalid-byte"),
        pytest.param("%F0%9F%98", id="decode_run-truncated-four-byte-sequence"),
        pytest.param("%C3(", id="decode_run-lead-byte-then-literal"),
        pytest.param("%41%E2%82", id="decode_run-valid-run-then-bad-run-leaves-all-unchanged"),
        pytest.param("a%41b%", id="trailing-percent"),
        pytest.param("%zz%41", id="non-hex-escape-leaves-valid-run-unchanged"),
        pytest.param("%4", id="one-hex-digit"),
        pytest.param("100%", id="bare-percent-at-end"),
    ],
)
def test_decode_uri_component_returns_the_text_unchanged_where_js_throws(text: str) -> None:
    assert decode_uri_component(text) == text


def make_decision(**overrides: Any) -> Any:
    base: dict[str, Any] = {
        "policy": "untrusted-to-exec",
        "reasons": [],
        "flows": [],
        "requires_confirmation": False,
        "tool_name": "run_shell",
        "sink": "exec",
    }
    return SimpleNamespace(**{**base, **overrides})


def make_flow(path: str, source_tool: str) -> Any:
    return SimpleNamespace(path=path, source_tool=source_tool)


@pytest.mark.parametrize(
    ("overrides", "code", "message"),
    [
        pytest.param(
            {},
            "untrusted-to-exec",
            "prompt-protection: run_shell denied (untrusted-to-exec; sink exec)",
            id="policy-is-the-code",
        ),
        pytest.param(
            {"policy": "plan-violation", "reasons": ["other-reason"]},
            "plan-violation",
            "prompt-protection: run_shell denied (plan-violation; sink exec)",
            id="policy-wins-over-reasons",
        ),
        pytest.param(
            {"policy": None, "reasons": ["first-reason", "second-reason"]},
            "first-reason",
            "prompt-protection: run_shell denied (first-reason; sink exec)",
            id="no-policy-uses-first-reason",
        ),
        pytest.param(
            {"policy": None, "reasons": []},
            "blocked",
            "prompt-protection: run_shell denied (blocked; sink exec)",
            id="no-policy-no-reasons-is-blocked",
        ),
        pytest.param(
            {"policy": "", "reasons": ["r"]},
            "",
            "prompt-protection: run_shell denied (; sink exec)",
            id="empty-policy-is-kept-like-nullish-coalescing",
        ),
        pytest.param(
            {"policy": None, "reasons": [""]},
            "",
            "prompt-protection: run_shell denied (; sink exec)",
            id="empty-first-reason-is-kept",
        ),
        pytest.param(
            {"requires_confirmation": True, "policy": "payment-confirm", "tool_name": "pay", "sink": "payment"},
            "payment-confirm",
            "prompt-protection: pay needs approval (payment-confirm; sink payment)",
            id="confirmation-says-needs-approval",
        ),
        pytest.param(
            {"flows": [make_flow("args.url", "fetch_page")]},
            "untrusted-to-exec",
            "prompt-protection: run_shell denied (untrusted-to-exec; sink exec; tainted: args.url from fetch_page)",
            id="one-flow",
        ),
        pytest.param(
            {"flows": [make_flow("args.url", "fetch_page"), make_flow("args.body", "read_mail")]},
            "untrusted-to-exec",
            "prompt-protection: run_shell denied "
            "(untrusted-to-exec; sink exec; tainted: args.url from fetch_page, args.body from read_mail)",
            id="two-flows-keep-order",
        ),
        pytest.param(
            {
                "flows": [
                    make_flow("args.url", "fetch_page"),
                    make_flow("args.body", "read_mail"),
                    make_flow("args.url", "fetch_page"),
                ]
            },
            "untrusted-to-exec",
            "prompt-protection: run_shell denied "
            "(untrusted-to-exec; sink exec; tainted: args.url from fetch_page, args.body from read_mail)",
            id="duplicate-flow-listed-once",
        ),
        pytest.param(
            {"flows": [make_flow("args.url", "fetch_page"), make_flow("args.url", "read_mail")]},
            "untrusted-to-exec",
            "prompt-protection: run_shell denied "
            "(untrusted-to-exec; sink exec; tainted: args.url from fetch_page, args.url from read_mail)",
            id="same-path-from-two-tools-is-two-entries",
        ),
    ],
)
def test_denial_builds_code_and_message(overrides: dict[str, Any], code: str, message: str) -> None:
    assert denial(make_decision(**overrides)) == Denial(code, message)
