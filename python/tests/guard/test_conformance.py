"""RED conformance tests for docs/CONFORMANCE.md (PY-4 holds behaviour 14; the rest land with later tasks)."""

import math
from collections.abc import Callable

import pytest
from prompt_protection.canonical import CanonicalJsonError, canonical_json


class IsoDate:
    """A Python stand-in for a JS Date: it serialises through its to_dict()."""

    def to_dict(self) -> str:
        return "1970-01-01T00:00:00.000Z"


def self_referencing() -> object:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    return cyclic


def nested_lists(levels: int) -> object:
    value: object = 1
    for _ in range(levels):
        value = [value]
    return value


def test_conformance_14_canonical_json_sorted_keys_to_dict_neg_zero_folded() -> None:
    value = {"b": [1, {"z": 1}], "a": IsoDate(), "c": -0.0}
    assert canonical_json(value) == '{"a":"1970-01-01T00:00:00.000Z","b":[1,{"z":1}],"c":0}'


def test_conformance_14_canonical_json_sorts_keys_by_utf16_code_unit() -> None:
    assert canonical_json({"\uff5e": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"\uff5e":1}'


def test_conformance_14_canonical_json_none_member_is_kept_as_null() -> None:
    assert canonical_json({"a": None, "b": 1}) == '{"a":null,"b":1}'


@pytest.mark.parametrize(
    ("make_value", "code"),
    [
        pytest.param(lambda: {"a": math.nan}, "non-finite", id="nan"),
        pytest.param(lambda: [math.inf], "non-finite", id="inf"),
        pytest.param(lambda: [-math.inf], "non-finite", id="negative-inf"),
        pytest.param(lambda: {1, 2}, "unsupported", id="set"),
        pytest.param(self_referencing, "cycle", id="cycle"),
        pytest.param(lambda: nested_lists(66), "depth", id="depth-over-64"),
    ],
)
def test_conformance_14_canonical_json_rejects_what_json_cannot_represent(
    make_value: Callable[[], object], code: str
) -> None:
    with pytest.raises(CanonicalJsonError) as info:
        canonical_json(make_value())
    assert info.value.code == code
