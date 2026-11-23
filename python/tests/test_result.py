"""RED tests for prompt_protection._result.JsResult (PY-7; plan D4, owner decision 5).

Every dataclass here is test-local, so the mixin is tested apart from any result type.
"""

from dataclasses import dataclass, field
from typing import ClassVar

from prompt_protection._result import JsResult


@dataclass(frozen=True)
class Leaf(JsResult):
    leaf_value: int
    note: str | None = None


@dataclass(frozen=True)
class Middle(JsResult):
    middle_leaf: Leaf
    other_leaves: list[Leaf] = field(default_factory=list)


@dataclass(frozen=True)
class Top(JsResult):
    top_middle: Middle
    top_label: str = "x"


@dataclass(frozen=True)
class Nullable(JsResult):
    _js_nullable: ClassVar[frozenset[str]] = frozenset({"lock_state", "drift_info"})
    lock_state: str | None = None
    drift_info: Leaf | None = None
    plain_field: int | None = None


@dataclass(frozen=True)
class Holder(JsResult):
    items: object = None
    some_value: int = 0


def test_js_nullable_defaults_to_an_empty_frozenset_on_the_base_and_on_subclasses() -> None:
    assert JsResult._js_nullable == frozenset()
    assert Leaf._js_nullable == frozenset()
    assert Nullable._js_nullable == frozenset({"lock_state", "drift_info"})


def test_field_names_become_camel_case_keys() -> None:
    assert Leaf(leaf_value=3).to_dict() == {"leafValue": 3}
    assert Top(top_middle=Middle(middle_leaf=Leaf(1))).to_dict() == {
        "topMiddle": {"middleLeaf": {"leafValue": 1}, "otherLeaves": []},
        "topLabel": "x",
    }


def test_a_none_field_is_left_out_like_a_js_optional_field() -> None:
    assert Leaf(leaf_value=1, note=None).to_dict() == {"leafValue": 1}
    assert Leaf(leaf_value=1, note="n").to_dict() == {"leafValue": 1, "note": "n"}


def test_a_none_field_named_in_js_nullable_is_emitted_as_null() -> None:
    assert Nullable().to_dict() == {"lockState": None, "driftInfo": None}


def test_a_nullable_field_that_holds_a_value_is_emitted_and_recursed() -> None:
    result = Nullable(lock_state="locked", drift_info=Leaf(leaf_value=2), plain_field=0)
    assert result.to_dict() == {"lockState": "locked", "driftInfo": {"leafValue": 2}, "plainField": 0}


def test_falsy_values_that_are_not_none_are_kept() -> None:
    assert Holder(items=[], some_value=0).to_dict() == {"items": [], "someValue": 0}
    assert Holder(items="", some_value=0).to_dict() == {"items": "", "someValue": 0}
    assert Holder(items=False, some_value=0).to_dict() == {"items": False, "someValue": 0}


def test_a_nested_results_own_js_nullable_applies_at_depth() -> None:
    holder = Holder(items=[Nullable()])
    assert holder.to_dict() == {"items": [{"lockState": None, "driftInfo": None}], "someValue": 0}


def test_nested_names_become_camel_case_at_every_depth_and_none_is_left_out_at_depth() -> None:
    top = Top(top_middle=Middle(middle_leaf=Leaf(leaf_value=1, note=None), other_leaves=[Leaf(2, "n")]))
    assert top.to_dict() == {
        "topMiddle": {
            "middleLeaf": {"leafValue": 1},
            "otherLeaves": [{"leafValue": 2, "note": "n"}],
        },
        "topLabel": "x",
    }


def test_a_list_of_results_recurses_and_keeps_order() -> None:
    middle = Middle(middle_leaf=Leaf(0), other_leaves=[Leaf(1), Leaf(2), Leaf(3)])
    assert [leaf["leafValue"] for leaf in middle.to_dict()["otherLeaves"]] == [1, 2, 3]


def test_a_list_nested_in_a_list_recurses() -> None:
    assert Holder(items=[[Leaf(1)], [Leaf(2), Leaf(3)]]).to_dict()["items"] == [
        [{"leafValue": 1}],
        [{"leafValue": 2}, {"leafValue": 3}],
    ]


def test_a_tuple_of_results_recurses_and_comes_out_as_a_list() -> None:
    items = Holder(items=(Leaf(1), Leaf(2))).to_dict()["items"]
    assert items == [{"leafValue": 1}, {"leafValue": 2}]
    assert isinstance(items, list)


def test_a_dict_value_recurses_and_the_dict_keys_are_left_as_they_are() -> None:
    holder = Holder(items={"snake_key": Leaf(1), "plain": [Leaf(2)], "n": 5})
    assert holder.to_dict()["items"] == {"snake_key": {"leafValue": 1}, "plain": [{"leafValue": 2}], "n": 5}


def test_plain_scalars_pass_through_unchanged() -> None:
    assert Holder(items=2.5).to_dict()["items"] == 2.5
    assert Holder(items="text").to_dict()["items"] == "text"
    assert Holder(items=True).to_dict()["items"] is True


def test_to_dict_returns_a_new_dict_and_leaves_the_result_unchanged() -> None:
    leaf = Leaf(leaf_value=1)
    first = leaf.to_dict()
    first["leafValue"] = 99
    assert leaf.leaf_value == 1
    assert leaf.to_dict() == {"leafValue": 1}
