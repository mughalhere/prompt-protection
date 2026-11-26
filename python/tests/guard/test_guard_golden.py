"""RED guard golden test (PY-23; plan design items 4 and 5, D12, owner decision 5).

tests/guard/__fixtures__/agent-flows.golden.json holds what Node 22 returned for every row of
datasets/agent-flows.jsonl. The decision is compared through ``GuardDecision.to_dict()``, so the JS keys are
what the golden checks. The recorded approval cards and locks are compared as they stand.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from steps import Recorder, run_row

from prompt_protection.guard import create_guard

REPO_ROOT = Path(__file__).resolve().parents[3]
ROWS = [
    json.loads(line)
    for line in (REPO_ROOT / "datasets" / "agent-flows.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
GOLDEN = {
    row["id"]: row
    for row in json.loads(
        (REPO_ROOT / "tests" / "guard" / "__fixtures__" / "agent-flows.golden.json").read_text(encoding="utf-8")
    )["rows"]
}


def project_decision(decision: dict[str, Any]) -> dict[str, Any]:
    """The fields the golden stores (D12), read from the camelCase dict form of a decision."""
    args = decision["argsAnalysis"]
    return {
        "action": decision["action"],
        "requiresConfirmation": decision["requiresConfirmation"],
        "reasons": decision["reasons"],
        "policy": decision.get("policy"),
        "sink": decision["sink"],
        "depth": decision["depth"],
        "flows": [{"kind": flow["kind"], "path": flow["path"]} for flow in decision["flows"]],
        "args": {
            "score": args["score"],
            "action": args["action"],
            "ruleIds": [match["rule"]["id"] for match in args["matches"]],
        },
    }


def test_the_golden_holds_one_entry_per_dataset_row_so_the_comparison_is_not_vacuous() -> None:
    assert len(ROWS) == 135
    assert list(GOLDEN) == [row["id"] for row in ROWS]


@pytest.mark.parametrize("row", ROWS, ids=[row["id"] for row in ROWS])
def test_decision_cards_and_locks_equal_the_js_golden_for_the_row(row: dict[str, Any]) -> None:
    recorder = Recorder()
    decision = run_row(create_guard, row, recorder)
    wanted = GOLDEN[row["id"]]
    assert project_decision(decision.to_dict()) == wanted["decision"]
    assert recorder.cards == wanted["cards"]
    assert recorder.locks == wanted["locks"]
