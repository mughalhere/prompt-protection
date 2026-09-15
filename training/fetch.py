#!/usr/bin/env python3
"""Fetch training/eval datasets from Hugging Face into data/raw/<name>.jsonl.

Each row is written as {"text", "label" (0/1), "source", "split"}.
The HF dataset card licence is re-verified against `licence_allowlist` in
config.yaml; a mismatch hard-fails unless --force is given.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

import yaml
from datasets import load_dataset
from huggingface_hub import HfApi, get_token
from huggingface_hub.errors import GatedRepoError, HfHubHTTPError, RepositoryNotFoundError

HERE = Path(__file__).resolve().parent
RAW_DIR = HERE / "data" / "raw"


def card_licence(api: HfApi, hf_id: str, allowlist: list[str] | None = None) -> tuple[str | None, str | None]:
    """Return (licence, gated) from the HF card; for a licence list, the first allowlisted one wins."""
    info = api.dataset_info(hf_id)
    card = info.card_data
    lic = None
    if card is not None:
        lic = card.get("license") if hasattr(card, "get") else getattr(card, "license", None)
    if lic is None:
        tags = [t for t in (info.tags or []) if t.startswith("license:")]
        lic = tags[0].split(":", 1)[1] if tags else None
    if isinstance(lic, list):
        ok = [x for x in lic if x in (allowlist or [])]
        lic = (ok or lic or [None])[0]
    return lic, info.gated


def map_label(raw, label_map: dict | None):
    if label_map is None:
        return None
    if isinstance(raw, bool):
        key = str(raw).lower()
        return label_map.get(key, label_map.get(raw))
    return label_map.get(raw, label_map.get(str(raw)))


def stratified_cap(rows: list[dict], cap: int | None, seed: int) -> list[dict]:
    if cap is None or len(rows) <= cap:
        return rows
    rng = random.Random(seed)
    by_label: dict[int, list[dict]] = {}
    for r in rows:
        by_label.setdefault(r["label"], []).append(r)
    total = len(rows)
    out: list[dict] = []
    for label, group in sorted(by_label.items()):
        k = round(cap * len(group) / total)
        out.extend(rng.sample(group, min(k, len(group))))
    rng.shuffle(out)
    return out[:cap]


def fetch_one(ds: dict, cfg: dict, api: HfApi, force: bool, warnings: list[str]) -> dict:
    name, hf_id = ds["name"], ds["hf_id"]
    summary = {"name": name, "hf_id": hf_id, "role": ds["role"], "status": "ok",
               "licence_card": None, "licence_config": ds.get("licence"),
               "rows_before_cap": 0, "rows": 0, "pos": 0, "neg": 0, "dropped_unmapped": 0}
    try:
        lic, gated = card_licence(api, hf_id, cfg["licence_allowlist"])
    except (RepositoryNotFoundError, HfHubHTTPError) as e:
        summary.update(status=f"missing ({type(e).__name__})")
        return summary
    summary["licence_card"] = lic
    if lic not in cfg["licence_allowlist"]:
        msg = f"{hf_id}: card licence {lic!r} not in allowlist"
        if not force:
            raise SystemExit(f"LICENCE FAIL: {msg} (use --force to override)")
        warnings.append(f"FORCED: {msg}")
    if lic != ds.get("licence"):
        warnings.append(f"{hf_id}: config says {ds.get('licence')!r}, card says {lic!r}")

    # HF `gated` is False, True, "auto" or "manual"; any truthy value needs a token.
    if gated and not get_token():
        summary.update(status=f"skipped (gated={gated}, no HF token)")
        warnings.append(f"{hf_id}: gated dataset skipped, set HF_TOKEN / `hf auth login` to include it")
        return summary

    label_map = ds.get("label_map")
    if label_map is not None:
        label_map = {str(k).lower() if isinstance(k, bool) else k: v for k, v in label_map.items()}
    rows: list[dict] = []
    for sub in ds["subsets"]:
        try:
            d = load_dataset(hf_id, sub["config"], split=sub["split"])
        except GatedRepoError as e:
            summary.update(status=f"skipped (gated: {str(e)[:80]})")
            return summary
        for ex in d:
            text = ex.get(ds["text_field"])
            if not isinstance(text, str) or not text.strip():
                continue
            if ds.get("label_field") is None:
                label = ds["fixed_label"]
            else:
                label = map_label(ex.get(ds["label_field"]), label_map)
                if label is None:
                    summary["dropped_unmapped"] += 1
                    continue
            rows.append({"text": text, "label": int(label), "source": name, "split": sub["split"]})
    summary["rows_before_cap"] = len(rows)
    rows = stratified_cap(rows, ds.get("cap"), cfg["seed"])
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    with (RAW_DIR / f"{name}.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    c = Counter(r["label"] for r in rows)
    summary.update(rows=len(rows), pos=c.get(1, 0), neg=c.get(0, 0))
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(HERE / "config.yaml"))
    ap.add_argument("--only", nargs="*", help="dataset names to fetch (default: all)")
    ap.add_argument("--force", action="store_true", help="include datasets failing the licence allowlist")
    args = ap.parse_args()
    cfg = yaml.safe_load(Path(args.config).read_text())
    api = HfApi()
    warnings: list[str] = []
    summaries = []
    for ds in cfg["datasets"]:
        if args.only and ds["name"] not in args.only:
            continue
        print(f"fetching {ds['hf_id']} ...", file=sys.stderr)
        summaries.append(fetch_one(ds, cfg, api, args.force, warnings))

    print(f"\n{'name':<12} {'licence':<12} {'role':<6} {'before':>8} {'rows':>8} {'pos':>7} {'neg':>7}  status")
    for s in summaries:
        print(f"{s['name']:<12} {str(s['licence_card']):<12} {s['role']:<6} {s['rows_before_cap']:>8} "
              f"{s['rows']:>8} {s['pos']:>7} {s['neg']:>7}  {s['status']}")
    print("\nexcluded by config:")
    for ex in cfg.get("excluded", []):
        print(f"  - {ex['hf_id']}: {ex['reason']}")
    if warnings:
        print("\nwarnings:")
        for w in warnings:
            print(f"  ! {w}")
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RAW_DIR / "fetch_summary.json").write_text(json.dumps(
        {"datasets": summaries, "excluded": cfg.get("excluded", []), "warnings": warnings}, indent=2))


if __name__ == "__main__":
    main()
