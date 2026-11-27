"""Direct tests for the ``envelope_invalid`` guard policy (twin of ``envelopeInvalid`` in src/guard/policy.ts).

Expected actions were taken from Node 22 by calling ``envelopeInvalid.evaluate`` on the built package
(dist/guard/index.cjs) with the same flows and sources. The policy id comes from the same object.
"""

from types import SimpleNamespace
from typing import Any

import pytest

from prompt_protection import guard as guard_package
from prompt_protection.guard.policy import DEFAULT_POLICIES, envelope_invalid, evaluate_policies


def make_context(flow_source_ids: list[str], lineages: dict[str, Any], sink: str = "none") -> Any:
    """A PolicyContext stand-in: ``lineages`` maps a source id to its edge ``from_`` list, or ``None``."""
    sources = {sid: SimpleNamespace(lineage=_edges(lineage)) for sid, lineage in lineages.items()}
    flows = [SimpleNamespace(source_id=sid, kind="text", identifier_kind=None) for sid in flow_source_ids]
    return SimpleNamespace(flows=flows, source_by_id=sources.get, sink=sink)


def _edges(lineage: list[str] | None) -> list[Any] | None:
    return None if lineage is None else [SimpleNamespace(from_=origin) for origin in lineage]


@pytest.mark.parametrize(
    ("flow_source_ids", "lineages", "expected"),
    [
        pytest.param([], {}, None, id="no-flows"),
        pytest.param(["s1"], {"s1": ["envelope:bad-signature"]}, "block", id="envelope-marker"),
        pytest.param(["s1"], {"s1": ["s0", "envelope:replayed"]}, "block", id="marker-on-a-later-edge"),
        pytest.param(["s1"], {"s1": ["envelope:"]}, "block", id="bare-marker-prefix"),
        pytest.param(["s1"], {"s1": ["handoff:forged"]}, None, id="handoff-marker-is-another-policy"),
        pytest.param(["s1"], {"s1": None}, None, id="no-lineage"),
        pytest.param(["s1"], {"s1": []}, None, id="empty-lineage"),
        pytest.param(["s9"], {}, None, id="flow-from-unknown-source"),
        pytest.param(["s1"], {"s1": ["envelope"]}, None, id="marker-needs-the-colon"),
        pytest.param(["s1"], {"s1": ["xenvelope:a"]}, None, id="marker-must-start-the-edge"),
        pytest.param(["s1"], {"s1": ["Envelope:a"]}, None, id="marker-is-case-sensitive"),
        pytest.param(["s1", "s2"], {"s1": ["s0"], "s2": ["envelope:expired"]}, "block", id="second-flow-carries-it"),
        pytest.param(["s9", "s2"], {"s2": ["envelope:x"]}, "block", id="unknown-source-then-marked-source"),
        pytest.param(["s1"], {"s1": ["s0"], "s2": ["envelope:x"]}, None, id="marked-source-without-a-flow"),
    ],
)
def test_envelope_invalid_blocks_only_a_flow_from_an_envelope_marker(
    flow_source_ids: list[str], lineages: dict[str, Any], expected: str | None
) -> None:
    assert envelope_invalid.evaluate(make_context(flow_source_ids, lineages)) == expected


@pytest.mark.parametrize("sink", ["none", "exec", "file-write", "payment"])
def test_envelope_invalid_ignores_the_sink(sink: str) -> None:
    ctx = make_context(["s1"], {"s1": ["envelope:forged"]}, sink=sink)
    assert envelope_invalid.evaluate(ctx) == "block"


def test_envelope_invalid_id_and_registration() -> None:
    assert envelope_invalid.id == "envelope-invalid"
    assert guard_package.envelope_invalid is envelope_invalid
    assert "envelope_invalid" in guard_package.__all__
    assert envelope_invalid in DEFAULT_POLICIES


@pytest.mark.parametrize(
    ("lineage", "action", "reasons", "policy"),
    [
        pytest.param(["envelope:forged"], "block", ["envelope-invalid"], "envelope-invalid", id="marked-flow-blocks"),
        pytest.param(["s0"], "allow", [], None, id="clean-flow-allows"),
    ],
)
def test_envelope_invalid_as_the_only_policy_decides_the_outcome(
    lineage: list[str], action: str, reasons: list[str], policy: str | None
) -> None:
    outcome = evaluate_policies([envelope_invalid], make_context(["s1"], {"s1": lineage}))
    assert (outcome.action, outcome.reasons, outcome.policy) == (action, reasons, policy)
