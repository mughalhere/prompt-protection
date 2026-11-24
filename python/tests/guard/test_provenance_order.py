"""RED tests for JS-ordered containment and cross-source flows (PY-11b, twin of src/guard/provenance.ts).

Six sources hold overlapping-by-five-words slices of one needle, so their shingle sets are disjoint. They are
registered out of needle order. A seventh holds five words and only matches char shingles. Expected rows come
from Node 22 running SourceIndex and detectFlows from src bundled with esbuild. JS iterates the needle Set in
token order, so the keys follow the needle and not registration or hash order.
"""

from types import SimpleNamespace
from typing import Any

import pytest

from prompt_protection.guard.provenance import (
    FlowThresholds,
    SourceIndex,
    TrustState,
    collect_leaves,
    detect_flows,
    identifier_values,
)
from prompt_protection.normalizer import normalize
from prompt_protection.shingle import build_shingles

WORDS = (
    "amber basalt cobalt dahlia ember fjord garnet harbor indigo jasper kelp lagoon marble nectar obsidian pewter "
    "quartz russet saffron topaz umber velvet willow xenon yarrow zircon argon bismuth cedar dune elm fern glacier "
    "hazel iris juniper kestrel lotus mango nutmeg opal poppy quince reed sorrel thistle"
).split(" ")
SLICES = [(0, 12), (7, 19), (14, 26), (21, 33), (28, 40), (35, 46)]
REGISTRATION = [4, 1, 5, 0, 3, 2]
THRESHOLDS = FlowThresholds(min_containment=0.05, min_char_containment=0.05)


def slice_text(start: int, end: int) -> str:
    return " ".join(WORDS[start:end])


NEEDLES = {
    "token-order": " ".join(WORDS),
    "blocks-reordered": " ".join(slice_text(*SLICES[i]) for i in (3, 0, 5, 2, 4, 1)),
}

# BEGIN GENERATED (node output)
CONTAINMENT_EXPECTED = {
    "token-order": [
        ("s0", 0.17073170731707318, 0.2),
        ("s1", 0.17073170731707318, 0.21428571428571427),
        ("s2", 0.17073170731707318, 0.21428571428571427),
        ("s3", 0.17073170731707318, 0.18571428571428572),
        ("s4", 0.17073170731707318, 0.18571428571428572),
        ("s5", 0.14634146341463414, 0.17142857142857143),
        ("c0", 0, 0.014285714285714285),
    ],
    "blocks-reordered": [
        ("s3", 0.10606060606060606, 0.1523809523809524),
        ("s0", 0.10606060606060606, 0.13333333333333333),
        ("s5", 0.09090909090909091, 0.11428571428571428),
        ("s2", 0.10606060606060606, 0.2),
        ("s4", 0.10606060606060606, 0.12380952380952381),
        ("s1", 0.10606060606060606, 0.18095238095238095),
        ("c0", 0, 0.009523809523809525),
    ],
}
FLOWS_EXPECTED = {
    "token-order": [
        ("s0", 0.2),
        ("s1", 0.21428571428571427),
        ("s2", 0.21428571428571427),
        ("s3", 0.18571428571428572),
        ("s4", 0.18571428571428572),
        ("s5", 0.17142857142857143),
    ],
    "blocks-reordered": [
        ("s3", 0.1523809523809524),
        ("s0", 0.13333333333333333),
        ("s5", 0.11428571428571428),
        ("s2", 0.2),
        ("s4", 0.12380952380952381),
        ("s1", 0.18095238095238095),
    ],
}
# END GENERATED


def make_source(source_id: str, tool: str, text: str) -> SimpleNamespace:
    normalized = normalize(text).normalized
    return SimpleNamespace(
        id=source_id,
        tool=tool,
        text=text,
        normalized=normalized,
        shingles=build_shingles(normalized, 1),
        identifiers=identifier_values(text),
    )


@pytest.fixture
def index() -> SourceIndex:
    sources = [(f"s{i}", f"t{i}", slice_text(*SLICES[i])) for i in REGISTRATION]
    sources.insert(2, ("c0", "tc", " ".join(WORDS[30:35])))
    built = SourceIndex(64, 200_000)
    for source in sources:
        built.add(make_source(*source))
    return built


def needle_of(case_id: str) -> Any:
    return build_shingles(normalize(NEEDLES[case_id]).normalized)


def run_flows(index: SourceIndex, case_id: str) -> Any:
    leaves = collect_leaves({"body": NEEDLES[case_id]})
    return detect_flows(leaves, index, TrustState(identifiers=set(), text=""), THRESHOLDS)


@pytest.mark.parametrize("case_id", list(NEEDLES))
def test_containment_keys_follow_the_needle_token_order(index: SourceIndex, case_id: str) -> None:
    expected = [row[0] for row in CONTAINMENT_EXPECTED[case_id]]
    assert [source.id for source in index.sources] != expected
    assert list(index.containment(needle_of(case_id))) == expected


@pytest.mark.parametrize("case_id", list(NEEDLES))
def test_containment_scores_match_node_in_node_order(index: SourceIndex, case_id: str) -> None:
    rows = [(key, score.word, score.char) for key, score in index.containment(needle_of(case_id)).items()]
    assert rows == CONTAINMENT_EXPECTED[case_id]


@pytest.mark.parametrize("case_id", list(NEEDLES))
def test_detect_flows_orders_cross_source_flows_like_node(index: SourceIndex, case_id: str) -> None:
    flows = run_flows(index, case_id).flows
    assert [flow.source_id for flow in flows] == [row[0] for row in FLOWS_EXPECTED[case_id]]


@pytest.mark.parametrize("case_id", list(NEEDLES))
def test_detect_flows_rows_match_node(index: SourceIndex, case_id: str) -> None:
    rows = [(flow.source_id, flow.strength) for flow in run_flows(index, case_id).flows]
    assert rows == FLOWS_EXPECTED[case_id]
    assert {flow.kind for flow in run_flows(index, case_id).flows} == {"content"}
