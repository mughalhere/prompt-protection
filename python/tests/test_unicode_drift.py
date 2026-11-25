"""RED test for the Unicode drift record in docs/PYTHON.md (PY-25; plan design item 6, owner decision 6, D16).

Node's NFKC and toLowerCase tables are tests/__fixtures__/unicode-node.json. Python's unicodedata moves with the
Python minor, so each minor's deltas against that table are recorded in docs/PYTHON.md as one fenced json block:

    ```json
    {"python": "3.12", "unidata": "15.0.0", "nfkc": ["00a0", "1f200-1f202"], "lower": [...]}
    ```

A block is any ```json fence that parses to an object with a "python" key. A range is "lo-hi" or a bare "cp", in
lowercase hex padded to 4 digits, sorted, merged when adjacent. A code point is in a delta when Python's
unicodedata.normalize("NFKC", ch) or ch.lower() differs from the Node table's value (the char itself if unlisted).
"""

import json
import re
import sys
import unicodedata
from functools import cache
from pathlib import Path
from typing import Any

import pytest

MINORS = ("3.10", "3.11", "3.12", "3.13")
UNIDATA = {"3.10": "13.0.0", "3.11": "14.0.0", "3.12": "15.0.0", "3.13": "15.1.0"}
KEYS = {"python", "unidata", "nfkc", "lower"}
RANGE_RE = re.compile(r"^([0-9a-f]{4,6})(?:-([0-9a-f]{4,6}))?$")
FENCE_RE = re.compile(r"^```json[ \t]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
RUNNING = f"{sys.version_info[0]}.{sys.version_info[1]}"
MAPPERS = {"nfkc": lambda ch: unicodedata.normalize("NFKC", ch), "lower": lambda ch: ch.lower()}


def compress(code_points: list[int]) -> list[str]:
    """Sorted code points to the doc's range strings."""
    out: list[str] = []
    start = prev = None
    for cp in [*code_points, None]:
        if start is not None and (cp is None or cp != prev + 1):  # type: ignore[operator]
            out.append(f"{start:04x}" if start == prev else f"{start:04x}-{prev:04x}")
            start = None
        if cp is not None:
            start = cp if start is None else start
            prev = cp
    return out


def expand(ranges: list[str]) -> list[int]:
    out: list[int] = []
    for item in ranges:
        match = RANGE_RE.match(item)
        assert match, f"not a canonical range string: {item!r}"
        low = int(match[1], 16)
        out.extend(range(low, int(match[2] or match[1], 16) + 1))
    return out


@cache
def node_tables() -> dict[str, dict[int, str]]:
    path = Path(__file__).resolve().parents[2] / "tests" / "__fixtures__" / "unicode-node.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return {name: {int(k, 16): v for k, v in data[name].items()} for name in MAPPERS}


@cache
def python_delta(name: str) -> list[str]:
    table, mapper = node_tables()[name], MAPPERS[name]
    differing = []
    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        ch = chr(cp)
        if mapper(ch) != table.get(cp, ch):
            differing.append(cp)
    return compress(differing)


def doc_text() -> str:
    path = Path(__file__).resolve().parents[2] / "docs" / "PYTHON.md"
    assert path.is_file(), f"docs/PYTHON.md is missing: {path}"
    return path.read_text(encoding="utf-8")


def drift_blocks(minor: str) -> list[dict[str, Any]]:
    found = []
    for fence in FENCE_RE.findall(doc_text()):
        try:
            block = json.loads(fence)
        except ValueError:
            continue
        if isinstance(block, dict) and block.get("python") == minor:
            found.append(block)
    return found


def the_block(minor: str) -> dict[str, Any]:
    blocks = drift_blocks(minor)
    assert len(blocks) == 1, f"docs/PYTHON.md needs exactly one json block with python {minor!r}, found {len(blocks)}"
    return blocks[0]


@pytest.mark.parametrize(
    ("code_points", "expected"),
    [
        ([], []),
        ([0xA0], ["00a0"]),
        ([0xA0, 0xA1, 0xA2], ["00a0-00a2"]),
        ([0xA0, 0xA2], ["00a0", "00a2"]),
        ([0xFF, 0x100, 0x1F200, 0x1F201], ["00ff-0100", "1f200-1f201"]),
    ],
)
def test_range_format_is_lowercase_padded_hex_with_adjacent_merge(code_points: list[int], expected: list[str]) -> None:
    assert compress(code_points) == expected
    assert expand(expected) == code_points


@pytest.mark.parametrize("minor", MINORS)
def test_doc_has_one_well_formed_block_per_supported_minor(minor: str) -> None:
    block = the_block(minor)
    assert set(block) == KEYS
    assert block["unidata"] == UNIDATA[minor]
    for name in MAPPERS:
        cps = expand(block[name])
        assert block[name] == compress(cps), f"{name} ranges must be sorted, merged and canonical"
        assert not [cp for cp in cps if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF]


@pytest.mark.skipif(RUNNING not in MINORS, reason="docs/PYTHON.md records Python 3.10 to 3.13 only")
@pytest.mark.parametrize("name", sorted(MAPPERS))
def test_running_python_delta_equals_doc_block(name: str) -> None:
    block = the_block(RUNNING)
    assert block["unidata"] == unicodedata.unidata_version
    assert block[name] == python_delta(name)
