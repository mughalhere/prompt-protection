"""Direct tests for ``js_trim``, ``tool_identities`` and ``from_function``.

Twins: ``String.prototype.trim`` (``js_trim``), ``toolIdentities`` in src/guard/pin.ts, and the resolver that
``createSinkResolver`` in src/guard/sinks.ts returns for a function (``from_function``, reached through
``create_sink_resolver``). Expected values come from Node 22, on the built package (dist/guard/index.cjs) for the
guard functions.
"""

from typing import Any

import pytest

from prompt_protection._js import js_trim
from prompt_protection.guard.pin import tool_identities
from prompt_protection.guard.sinks import create_sink_resolver

# node -e 'for(let c=0;c<0x110000;c++)if(String.fromCodePoint(c).trim()==="")console.log(c.toString(16))'
JS_TRIM_WHITESPACE = [
    0x9, 0xA, 0xB, 0xC, 0xD, 0x20, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
    0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
]  # fmt: skip
# str.strip() treats these as whitespace and JS trim does not (U+0085, U+001C..U+001F), or the reverse (U+FEFF).
KEPT_AT_THE_EDGES = [0x85, 0x1C, 0x1D, 0x1E, 0x1F, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0xAD, 0x0, 0xFFFE]


def hex_id(code_point: int) -> str:
    return f"U+{code_point:04X}"


@pytest.mark.parametrize("code_point", JS_TRIM_WHITESPACE, ids=hex_id)
def test_js_trim_strips_each_js_whitespace_code_point_from_both_ends(code_point: int) -> None:
    space = chr(code_point)
    assert js_trim(f"{space}x{space}") == "x"
    assert js_trim(f"{space}{space}x") == "x"
    assert js_trim(f"x{space}{space}") == "x"


@pytest.mark.parametrize("code_point", KEPT_AT_THE_EDGES, ids=hex_id)
def test_js_trim_keeps_code_points_that_js_does_not_treat_as_whitespace(code_point: int) -> None:
    edge = chr(code_point)
    assert js_trim(f"{edge}x{edge}") == f"{edge}x{edge}"


def test_js_trim_empties_exactly_the_js_whitespace_code_points() -> None:
    assert {cp for cp in range(0x110000) if js_trim(chr(cp)) == ""} == set(JS_TRIM_WHITESPACE)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("", "", id="empty"),
        pytest.param("   ", "", id="only-whitespace"),
        pytest.param("a b", "a b", id="no-edge-whitespace"),
        pytest.param("  a  b  ", "a  b", id="inner-whitespace-kept"),
        pytest.param("﻿\t a \n　", "a", id="mixed-whitespace-both-ends"),
        pytest.param(" x ", "x", id="line-separators"),
        pytest.param(" \x85 x \x85 ", "\x85 x \x85", id="c1-control-kept-inside"),
        pytest.param("😀 ", "😀", id="astral-before-trailing-space"),
        pytest.param(" \ud83d ", "\ud83d", id="lone-surrogate"),
        pytest.param("x\n", "x", id="trailing-only"),
        pytest.param("\tx", "x", id="leading-only"),
    ],
)
def test_js_trim_matches_string_prototype_trim(text: str, expected: str) -> None:
    assert js_trim(text) == expected


def identity(name: str, description: str = "", schema: Any = None, annotations: Any = None) -> dict[str, Any]:
    return {"name": name, "description": description, "schema": schema, "annotations": annotations}


@pytest.mark.parametrize(
    ("tools", "expected"),
    [
        pytest.param([], [], id="empty-sequence"),
        pytest.param({}, [], id="empty-mapping"),
        pytest.param(
            [
                {
                    "name": "a",
                    "description": "da",
                    "inputSchema": {"t": "object"},
                    "annotations": {"readOnlyHint": True},
                },
                {"name": "b"},
            ],
            [
                ("a", identity("a", "da", {"t": "object"}, {"readOnlyHint": True})),
                ("b", identity("b")),
            ],
            id="sequence-names-each-tool-by-its-own-name",
        ),
        pytest.param(
            [{"description": "x"}, {"name": ""}, {"name": 5}, {"name": None}, {"name": "ok"}],
            [("ok", identity("ok"))],
            id="sequence-skips-a-missing-empty-or-non-string-name",
        ),
        pytest.param(
            {"k": {"name": "other", "description": "d"}},
            [("k", identity("k", "d"))],
            id="mapping-key-beats-the-tools-own-name",
        ),
        pytest.param({"": {}}, [("", identity(""))], id="mapping-keeps-an-empty-key"),
        pytest.param(
            {"p": {"parameters": {"x": 1}}, "q": {"inputSchema": {"y": 2}, "parameters": {"x": 1}}},
            [("p", identity("p", schema={"x": 1})), ("q", identity("q", schema={"y": 2}))],
            id="parameters-only-when-no-input-schema",
        ),
        pytest.param(
            [{"name": "a", "description": "first"}, {"name": "b"}, {"name": "a", "description": "second"}],
            [("a", identity("a", "second")), ("b", identity("b"))],
            id="duplicate-name-last-wins-first-position-stays",
        ),
        pytest.param(
            {
                "z": {"description": None, "annotations": None, "inputSchema": None, "parameters": None},
                "a": {},
            },
            [("z", identity("z")), ("a", identity("a"))],
            id="null-fields-and-mapping-order",
        ),
    ],
)
def test_tool_identities_maps_name_to_identity(tools: Any, expected: list[tuple[str, dict[str, Any]]]) -> None:
    assert list(tool_identities(tools).items()) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        pytest.param("send_email", "none", id="explicit-sink-beats-the-default-email"),
        pytest.param("get_thing", "exec", id="explicit-sink-beats-the-default-none"),
        pytest.param("blank", "", id="empty-string-is-an-answer"),
        pytest.param("custom_tool", "custom", id="custom-sink-passes-through"),
        pytest.param("nulled", "none", id="none-falls-back-to-the-default"),
        pytest.param("send_mail_x", "email", id="unanswered-email-name"),
        pytest.param("fetch_url", "none", id="unanswered-read-verb"),
        pytest.param("run_shell", "exec", id="unanswered-exec-name"),
        pytest.param("pay_invoice", "payment", id="unanswered-payment-name"),
        pytest.param("zzz", "none", id="unanswered-unknown-name"),
    ],
)
def test_from_function_uses_the_answer_unless_it_is_none(name: str, expected: str) -> None:
    answers = {"send_email": "none", "get_thing": "exec", "blank": "", "custom_tool": "custom", "nulled": None}
    resolve = create_sink_resolver(answers.get)
    assert resolve(name) == expected


def test_from_function_passes_the_tool_name_through_on_every_call() -> None:
    seen: list[str] = []

    def record(tool_name: str) -> None:
        seen.append(tool_name)

    resolve = create_sink_resolver(record)
    assert [resolve("a"), resolve("b"), resolve("a")] == ["none", "none", "none"]
    assert seen == ["a", "b", "a"]


def test_from_function_lets_a_resolver_error_propagate() -> None:
    def explode(tool_name: str) -> str:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        create_sink_resolver(explode)("x")
