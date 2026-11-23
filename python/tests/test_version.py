"""Version lockstep guards (plan owner decision 4, D25): Python, npm and package metadata share one version."""

import json
from importlib.metadata import version
from pathlib import Path

import prompt_protection


def test_dunder_version_equals_package_json_version(repo_root: Path) -> None:
    package = json.loads((repo_root / "package.json").read_text(encoding="utf-8"))
    assert prompt_protection.__version__ == package["version"]


def test_installed_metadata_version_equals_dunder_version() -> None:
    assert version("prompt-protection") == prompt_protection.__version__
