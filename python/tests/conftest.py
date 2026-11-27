import json
import signal
from collections.abc import Iterator
from functools import cache
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_PATH = REPO_ROOT / "tests" / "__fixtures__" / "analyze.golden.json"
RULES_JSON_PATH = REPO_ROOT / "python" / "src" / "prompt_protection" / "_data" / "rules.json"
DEADLINE_SECONDS = 2


@cache
def load_golden() -> dict[str, Any]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Give any test that names ``golden_case`` one run per analyze golden case, id'd by index and origin."""
    if "golden_case" in metafunc.fixturenames:
        cases = load_golden()["cases"]
        metafunc.parametrize("golden_case", cases, ids=[f"{i:04d}-{c['origin']}" for i, c in enumerate(cases)])


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def golden() -> dict[str, Any]:
    return load_golden()


@pytest.fixture(scope="session")
def rules_json() -> dict[str, Any]:
    return json.loads(RULES_JSON_PATH.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@pytest.fixture(scope="session")
def rules_digest(repo_root: Path) -> dict[str, str]:
    return json.loads((repo_root / "tests" / "__fixtures__" / "rules-digest.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@pytest.fixture
def deadline() -> Iterator[None]:
    """Fail with TimeoutError instead of hanging when the test body does not finish in DEADLINE_SECONDS."""
    if not hasattr(signal, "setitimer"):
        pytest.skip("needs SIGALRM")

    def on_alarm(signum: int, frame: object) -> None:
        raise TimeoutError(f"did not finish within {DEADLINE_SECONDS}s")

    previous = signal.signal(signal.SIGALRM, on_alarm)
    signal.setitimer(signal.ITIMER_REAL, DEADLINE_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
