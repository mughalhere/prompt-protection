#!/usr/bin/env python3
"""Deduplicate fetched rows and enforce train/eval separation.

1. Exact dedupe on a cheap key (lowercase, whitespace-collapsed). With
   --normalized-dir (default data/norm/ when it exists) the key is the `norm`
   field produced by the real JS normalizer (normalize.mjs) instead.
2. MinHash LSH (word 5-shingles, 128 perms, Jaccard >= 0.8) within train.
3. Cross-split: any train row near-duplicate of ANY eval row is dropped.

Writes data/dedupe/{train,eval}.jsonl and data/dedupe/stats.json.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml
from datasketch import MinHash, MinHashLSH

HERE = Path(__file__).resolve().parent
RAW_DIR = HERE / "data" / "raw"
NORM_DIR = HERE / "data" / "norm"
OUT_DIR = HERE / "data" / "dedupe"
WS = re.compile(r"\s+")


def cheap_norm(text: str) -> str:
    return WS.sub(" ", text.lower()).strip()


def shingles(norm: str, k: int) -> set[bytes]:
    words = norm.split()
    if len(words) < k:
        return {" ".join(words).encode("utf-8")}
    return {" ".join(words[i:i + k]).encode("utf-8") for i in range(len(words) - k + 1)}


def minhash(norm: str, k: int, perms: int) -> MinHash:
    m = MinHash(num_perm=perms)
    m.update_batch(list(shingles(norm, k)))
    return m


def load_rows(cfg: dict, src_dir: Path) -> tuple[list[dict], list[dict]]:
    """Datasets from config.yaml plus every benign_<name>.jsonl (mine_benign.py output, always train)."""
    train, eval_ = [], []
    paths = [(src_dir / f"{ds['name']}.jsonl", ds["role"]) for ds in cfg["datasets"]]
    paths += [(p, "train") for p in sorted(src_dir.glob("benign_*.jsonl"))]
    for path, role in paths:
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                r["norm"] = r.get("text_normalized") or cheap_norm(r["text"])
                (train if role == "train" else eval_).append(r)
    return train, eval_


def exact_dedupe(rows: list[dict], drops: Counter) -> list[dict]:
    seen: set[str] = set()
    out = []
    for r in rows:
        if r["norm"] in seen:
            drops[r["source"]] += 1
            continue
        seen.add(r["norm"])
        out.append(r)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(HERE / "config.yaml"))
    ap.add_argument("--normalized-dir", default=None,
                    help="dir of <name>.jsonl with a `norm` field (default: data/norm/ if present)")
    args = ap.parse_args()
    cfg = yaml.safe_load(Path(args.config).read_text())
    dd = cfg["dedupe"]
    k, perms, thr = dd["shingle_words"], dd["minhash_perms"], dd["jaccard_threshold"]

    src = Path(args.normalized_dir) if args.normalized_dir else (NORM_DIR if NORM_DIR.exists() else RAW_DIR)
    train, eval_ = load_rows(cfg, src)
    stats: dict = {"source_dir": str(src), "input": {"train": len(train), "eval": len(eval_)},
                   "exact_drops": {}, "near_drops": {}, "cross_split_drops": {}, "per_source": {}}

    exact = Counter()
    train = exact_dedupe(train, exact)
    eval_ = exact_dedupe(eval_, exact)
    stats["exact_drops"] = dict(exact)

    # Eval rows go into the LSH first so train rows colliding with them are dropped.
    lsh = MinHashLSH(threshold=thr, num_perm=perms)
    for i, r in enumerate(eval_):
        lsh.insert(f"e{i}", minhash(r["norm"], k, perms))

    near, cross = Counter(), Counter()
    kept_train = []
    for i, r in enumerate(train):
        m = minhash(r["norm"], k, perms)
        hits = lsh.query(m)
        if any(h.startswith("e") for h in hits):
            cross[r["source"]] += 1
            continue
        if hits:
            near[r["source"]] += 1
            continue
        lsh.insert(f"t{i}", m)
        kept_train.append(r)
    stats["near_drops"] = dict(near)
    stats["cross_split_drops"] = dict(cross)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, rows in (("train", kept_train), ("eval", eval_)):
        with (OUT_DIR / f"{name}.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps({kk: v for kk, v in r.items() if kk != "norm"}, ensure_ascii=False) + "\n")
        per = defaultdict(lambda: {"rows": 0, "pos": 0, "neg": 0})
        for r in rows:
            per[r["source"]]["rows"] += 1
            per[r["source"]]["pos" if r["label"] else "neg"] += 1
        stats["per_source"][name] = dict(per)
    stats["output"] = {"train": len(kept_train), "eval": len(eval_)}
    (OUT_DIR / "stats.json").write_text(json.dumps(stats, indent=2))

    print(f"source dir: {src}")
    print(f"train {stats['input']['train']} -> {len(kept_train)}  (exact {sum(exact.values())}, "
          f"near {sum(near.values())}, cross-split {sum(cross.values())})")
    print(f"eval  {stats['input']['eval']} -> {len(eval_)}")
    for split, per in stats["per_source"].items():
        for s, v in sorted(per.items()):
            print(f"  {split:<5} {s:<12} rows={v['rows']:>6} pos={v['pos']:>6} neg={v['neg']:>6}")


if __name__ == "__main__":
    main()
