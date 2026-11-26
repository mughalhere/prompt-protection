"""README quickstarts run as written (PY-26, F-012, owner decisions 4 and 6 of py-port-4-5)."""

import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import pytest

FENCE = re.compile(r"^```(\w*)[ \t]*\n(.*?)^```[ \t]*$", re.DOTALL | re.MULTILINE)
TIMEOUT_SECONDS = 30
NO_NETWORK_LAUNCHER = (
    "import runpy, socket, sys\n"
    "def _deny(*a, **k):\n"
    "    raise OSError('network disabled in README test')\n"
    "socket.socket.connect = _deny\n"
    "socket.create_connection = _deny\n"
    "runpy.run_path(sys.argv[1], run_name='__main__')\n"
)


class Block(NamedTuple):
    source: str
    expected: str | None


def python_blocks(markdown: str) -> list[Block]:
    """Each ``python`` fence, paired with the next fence's text when that fence is a ``text`` block."""
    fences = list(FENCE.finditer(markdown))
    blocks = []
    for i, fence in enumerate(fences):
        if fence.group(1) != "python":
            continue
        following = fences[i + 1] if i + 1 < len(fences) else None
        expected = following.group(2) if following is not None and following.group(1) == "text" else None
        blocks.append(Block(fence.group(2), expected))
    return blocks


def root_python_section(root_readme: str) -> str:
    start = root_readme.index("## Python (Preview)")
    end = root_readme.index("\n---", start)
    return root_readme[start:end]


@pytest.fixture(scope="module")
def python_readme_text(repo_root: Path) -> str:
    return (repo_root / "python" / "README.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def root_section_text(repo_root: Path) -> str:
    return root_python_section((repo_root / "README.md").read_text(encoding="utf-8"))


def collect_cases() -> list:
    repo_root = Path(__file__).resolve().parents[2]
    sources = {
        "root-readme": root_python_section((repo_root / "README.md").read_text(encoding="utf-8")),
        "python-readme": (repo_root / "python" / "README.md").read_text(encoding="utf-8"),
    }
    return [
        pytest.param(block, id=f"{name}-block{i}")
        for name, text in sources.items()
        for i, block in enumerate(python_blocks(text))
    ]


@pytest.mark.parametrize("block", collect_cases())
def test_python_block_runs_and_prints_its_documented_output(block: Block, tmp_path: Path) -> None:
    script = tmp_path / "block.py"
    script.write_text(block.source, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-c", NO_NETWORK_LAUNCHER, str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    if block.expected is not None:
        assert result.stdout.strip() == block.expected.strip()


def test_root_readme_python_section_has_a_checked_block(root_section_text: str) -> None:
    blocks = python_blocks(root_section_text)
    assert len(blocks) >= 1
    assert blocks[0].expected is not None


def test_python_readme_has_a_python_quickstart_block(python_readme_text: str) -> None:
    assert len(python_blocks(python_readme_text)) >= 1


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param(r"identical decisions on the published corpus", id="corpus-parity-phrase-D6"),
        pytest.param(r"CPython 3\.10-3\.13", id="tested-range-F012"),
        pytest.param(r"2026-11-23", id="tested-range-date-F012"),
        pytest.param(r"\b4\.5\b", id="parity-minor-D4"),
        pytest.param(r"(?i)\blockstep\b", id="version-policy-D4"),
    ],
)
def test_python_readme_states_required_fact(python_readme_text: str, pattern: str) -> None:
    assert re.search(pattern, python_readme_text), pattern


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param(r"ML classifier", id="ml-classifier"),
        pytest.param(r"(?i)spotlight", id="spotlight"),
        pytest.param(r"(?i)canar", id="canary"),
        pytest.param(r"\bATR\b", id="atr"),
        pytest.param(r"\bOTel\b", id="otel"),
        pytest.param(r"(?i)\baudit\b", id="audit"),
        pytest.param(r"EdDSA envelopes", id="eddsa-envelopes"),
        pytest.param(r"\banalyze_output\b", id="analyze-output"),
        pytest.param(r"\bemit_output_log\b", id="emit-output-log"),
    ],
)
def test_python_readme_lists_deferred_item(python_readme_text: str, pattern: str) -> None:
    assert re.search(pattern, python_readme_text), pattern


def test_python_readme_says_the_listed_items_are_deferred(python_readme_text: str) -> None:
    assert re.search(r"(?i)deferred|not yet ported", python_readme_text)


def test_python_readme_states_eddsa_fails_closed_with_unknown_kid(python_readme_text: str) -> None:
    assert re.search(r"EdDSA[^.]*fail(s|ed)? closed[^.]*`unknown-kid`", python_readme_text)
