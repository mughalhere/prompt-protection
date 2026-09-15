#!/usr/bin/env python3
"""Stage (and optionally upload) the CC-BY-4.0 datasets to the Hugging Face Hub.

Dry-run by default: writes training/hf_staging/ with the three JSONL files and a
dataset card whose benchmark table is taken from bench/results.json. Upload only
with --upload and HF_TOKEN set (user action).
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASETS = ROOT / "datasets"
STAGING = ROOT / "training" / "hf_staging"
FILES = ["attacks.jsonl", "benign-hard.jsonl", "agent-flows.jsonl"]
DEFAULT_REPO = "promptprotection/agent-security-datasets"  # the Hugging Face organisation


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def bench_table() -> str:
    results = json.loads((ROOT / "bench" / "results.json").read_text())
    regex = results["modes"]["regex"]
    rows = ["| Set | N | Recall (regex) | FP rate (regex) |", "|---|---|---|---|"]
    for name, r in regex.items():
        rows.append(f"| {name} | {r['n']} | {pct(r['recall'])} | {pct(r['fpr'])} |")
    af = results["agentFlows"]
    rows.append(f"| agent-flows (guard) | {af['n']} | block-recall {pct(af['attackBlockRecall'])} | benign FPR {pct(af['benignFpr'])} |")
    return "\n".join(rows)


def card() -> str:
    readme = (DATASETS / "README.md").read_text()
    front = (
        "---\n"
        "license: cc-by-4.0\n"
        "task_categories:\n  - text-classification\n"
        "language:\n  - en\n  - multilingual\n"
        "size_categories:\n  - n<1K\n"
        "tags:\n  - prompt-injection\n  - agent-security\n  - tool-call-guard\n  - benchmark\n"
        "pretty_name: prompt-protection agent security datasets\n"
        "---\n\n"
    )
    return front + readme + "\n\n## Benchmark snapshot (from bench/results.json)\n\n" + bench_table() + "\n"


def stage() -> None:
    STAGING.mkdir(parents=True, exist_ok=True)
    for f in FILES:
        shutil.copy(DATASETS / f, STAGING / f)
    shutil.copy(DATASETS / "LICENSE", STAGING / "LICENSE")
    (STAGING / "README.md").write_text(card())
    print(f"staged {len(FILES)} files + card in {STAGING}")


def upload(repo: str | None) -> None:
    from huggingface_hub import HfApi  # dev-time dependency

    api = HfApi()
    if repo is None:
        repo = DEFAULT_REPO
    try:
        api.create_repo(repo, repo_type="dataset", exist_ok=True)
    except Exception as err:  # noqa: BLE001
        if "403" not in str(err):
            raise
        namespace = repo.split("/", 1)[0]
        raise SystemExit(
            f"403 creating {repo}. The token has no write rights on the '{namespace}' namespace.\n"
            "Fix: huggingface.co/settings/tokens -> edit the token -> Organization permissions -> "
            f"add '{namespace}' with Repos write. Or pass --repo <your-username>/<name> to publish under your own account."
        ) from err
    api.upload_folder(folder_path=str(STAGING), repo_id=repo, repo_type="dataset")
    print(f"uploaded to https://huggingface.co/datasets/{repo}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--upload", action="store_true", help="upload staged folder (needs HF_TOKEN)")
    ap.add_argument("--repo", default=None, help="<namespace>/<name>; default promptprotection/agent-security-datasets")
    args = ap.parse_args()
    stage()
    if args.upload:
        upload(args.repo)
