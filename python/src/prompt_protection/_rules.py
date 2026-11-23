"""The exported rule pack and the JS ``RegExp#exec`` loop over it, in UTF-16 offsets."""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from typing import Any

from prompt_protection._js import code_units
from prompt_protection._result import JsResult

__all__ = ["DEFERRED_REFERENCE_RULE_IDS", "RULES", "RULES_VERSION", "Rule", "match_spans"]

_FLAGS = re.ASCII | re.IGNORECASE


@dataclass(frozen=True, slots=True)
class Rule(JsResult):
    id: str
    source: str
    weight: int
    category: str
    precision: str
    pattern: re.Pattern[str]
    mappings: Mapping[str, Any] | None = None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise like a JS rule; the compiled ``pattern`` is left out because ``source`` holds it."""
        return {key: value for key, value in JsResult.to_dict(self).items() if key != "pattern"}


def _load() -> dict[str, Any]:
    text = resources.files("prompt_protection").joinpath("_data/rules.json").read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


def _build(entry: dict[str, Any]) -> Rule:
    return Rule(
        id=entry["id"],
        source=entry["source"],
        weight=entry["weight"],
        category=entry["category"],
        precision=entry["precision"],
        pattern=re.compile(entry["source"], _FLAGS),
        mappings=entry.get("mappings"),
    )


_DATA = _load()
RULES: tuple[Rule, ...] = tuple(_build(entry) for entry in _DATA["rules"])
RULES_VERSION: str = _DATA["rulesVersion"]
DEFERRED_REFERENCE_RULE_IDS: tuple[str, ...] = tuple(_DATA["deferredReferenceRuleIds"])


def match_spans(pattern: re.Pattern[str], text: str) -> list[tuple[int, int]]:
    """Return every ``(start, end)`` the JS ``exec`` loop with ``lastIndex++`` after an empty match finds.

    Offsets count UTF-16 code units. Matching runs over a string of code units, so an empty
    match between the halves of a surrogate pair is reported as Node reports it.
    """
    haystack = text if text.isascii() else "".join(map(chr, code_units(text)))
    spans: list[tuple[int, int]] = []
    pos = 0
    while pos <= len(haystack):
        found = pattern.search(haystack, pos)
        if found is None:
            break
        start, end = found.span()
        spans.append((start, end))
        pos = end + 1 if end == start else end
    return spans
