"""EdDSA keys passed to the guard envelope methods raise DeferredFeatureError.

A blocked 'malformed' source in place of the raise is the silent degrade that a raise prevents.
"""

from typing import Any

import pytest

from prompt_protection import DeferredFeatureError
from prompt_protection.envelope import seal
from prompt_protection.guard import create_guard

KEY = {"alg": "HS256", "secret": "memory-and-handoff-secret", "kid": "m1"}
EDDSA_KEY = {"alg": "EdDSA", "kid": "ed-1"}
KEY_SETS = {
    "eddsa-alone": EDDSA_KEY,
    "eddsa-after-hs256": [KEY, EDDSA_KEY],
    "eddsa-before-hs256": [EDDSA_KEY, KEY],
}


@pytest.fixture(params=KEY_SETS.values(), ids=KEY_SETS.keys())
def keys(request: pytest.FixtureRequest) -> Any:
    return request.param


@pytest.mark.parametrize("method", ["taint_envelope", "absorb_sealed"])
def test_d5_envelope_and_handoff_opens_raise_for_an_eddsa_key(method: str, keys: Any) -> None:
    env = seal("Notes: a valid envelope", KEY, label="user")
    with pytest.raises(DeferredFeatureError, match="EdDSA"):
        getattr(create_guard(), method)(env, keys)


def test_d5_memory_read_sealed_raises_for_an_eddsa_key(keys: Any) -> None:
    writer = create_guard(memory={"key": KEY})
    entry = writer.seal_memory_entry(writer.taint_memory_write("note", "Alice prefers Thursday.").entry)
    with pytest.raises(DeferredFeatureError, match="EdDSA"):
        create_guard().memory_read_sealed([entry], keys)
