"""RED tests for the deferred create_guard options.

An option for a feature the Python package defers raises DeferredFeatureError at create_guard, whatever fail_mode
says, and the message names the feature. The generic logger option is accepted and never raised on.
"""

from types import SimpleNamespace
from typing import Any

import pytest

from prompt_protection import DeferredFeatureError
from prompt_protection.guard import ToolCall, create_guard

ML_MESSAGE = r"(?i)\bml\b"
SPOTLIGHT_MESSAGE = r"(?i)spotlight"
EDDSA_MESSAGE = "EdDSA"
HS256_KEY = {"alg": "HS256", "secret": "k" * 32, "kid": "k1"}
EDDSA_KEY = {"alg": "EdDSA", "publicKey": object(), "privateKey": object(), "kid": "k2"}

DEFERRED_OPTIONS = [
    pytest.param({"spotlight": "delimit"}, SPOTLIGHT_MESSAGE, id="spotlight-delimit"),
    pytest.param({"spotlight": "datamark"}, SPOTLIGHT_MESSAGE, id="spotlight-datamark"),
    pytest.param({"spotlight": "encode"}, SPOTLIGHT_MESSAGE, id="spotlight-encode"),
    pytest.param({"spotlight": {"mode": "datamark"}}, SPOTLIGHT_MESSAGE, id="spotlight-options"),
    pytest.param({"spotlight": {"mode": "datamark", "marker": "^"}}, SPOTLIGHT_MESSAGE, id="spotlight-marker"),
    pytest.param({"analyze_options": {"ml": "escalate"}}, ML_MESSAGE, id="ml-escalate"),
    pytest.param({"analyze_options": {"ml": "hybrid"}}, ML_MESSAGE, id="ml-hybrid"),
    pytest.param({"analyze_options": {"ml": "bogus"}}, ML_MESSAGE, id="ml-unknown"),
    pytest.param({"memory": {"key": EDDSA_KEY}}, EDDSA_MESSAGE, id="memory-eddsa-key"),
    pytest.param({"memory": {"key": [HS256_KEY, EDDSA_KEY]}}, EDDSA_MESSAGE, id="memory-eddsa-key-in-a-list"),
]

ACCEPTED_OPTIONS = [
    pytest.param({"spotlight": None}, id="spotlight-none"),
    pytest.param({"analyze_options": {"ml": "off"}}, id="ml-off"),
    pytest.param({"analyze_options": {"ml": None}}, id="ml-none"),
    pytest.param({"memory": {"key": HS256_KEY}}, id="memory-hs256-key"),
    pytest.param({"memory": {"key": [HS256_KEY]}}, id="memory-hs256-key-in-a-list"),
    pytest.param({"logger": SimpleNamespace(log=lambda event: None)}, id="logger"),
    pytest.param({"logger": SimpleNamespace(log=lambda event: None), "fail_mode": "open"}, id="logger-open"),
]


@pytest.mark.parametrize("fail_mode", ["closed", "open"])
@pytest.mark.parametrize(("options", "message"), DEFERRED_OPTIONS)
def test_a_deferred_option_raises_deferred_feature_error_naming_the_feature(
    options: dict[str, Any], message: str, fail_mode: str
) -> None:
    with pytest.raises(DeferredFeatureError, match=message) as info:
        create_guard(fail_mode=fail_mode, **options)
    assert isinstance(info.value, ValueError)


@pytest.mark.parametrize("options", ACCEPTED_OPTIONS)
def test_an_option_that_is_not_deferred_builds_a_working_guard(options: dict[str, Any]) -> None:
    guard = create_guard(**options)
    decision = guard.check_tool_call(ToolCall(tool_name="search", args={"q": "x"}))
    assert decision.action == "allow"


@pytest.mark.parametrize("fail_mode", ["closed", "open"])
def test_a_per_turn_ml_option_raises_whatever_the_fail_mode(fail_mode: str) -> None:
    guard = create_guard(fail_mode=fail_mode)
    with pytest.raises(DeferredFeatureError, match=ML_MESSAGE):
        guard.analyze_user_turn("hello", ml="escalate")


def test_a_per_turn_ml_off_scores_normally() -> None:
    assert create_guard().analyze_user_turn("hello", ml="off").action == "allow"
