"""Package-root export and creation-time size check for the session API (PY-8; JS src/index.ts line 10)."""

import pytest

import prompt_protection
from prompt_protection import session


@pytest.mark.parametrize("name", ["create_protection_session", "ProtectionSession"])
def test_the_package_root_exports_the_session_api_from_the_session_module(name: str) -> None:
    assert name in prompt_protection.__all__
    assert getattr(prompt_protection, name) is getattr(session, name)


@pytest.mark.parametrize("size", [-1, -2, -1000])
def test_a_negative_max_blocked_history_raises_value_error_at_creation(size: int) -> None:
    with pytest.raises(ValueError, match="max_blocked_history"):
        session.create_protection_session(max_blocked_history=size)
