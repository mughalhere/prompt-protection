#!/usr/bin/env python3
"""Mine licence-clean benign (label 0) rows into data/raw/benign_<name>.jsonl.

Sources and caps live under `benign:` in config.yaml. Rows containing a trigger
word (`benign.trigger_words`) are selected first, oversampled, never synthesised , 
then the cap is filled with a seeded random sample. Every candidate is checked
against the eval sets (exact + MinHash, same rule as dedupe.py) and dropped on a hit.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd
import yaml
from datasets import load_dataset
from datasketch import MinHash, MinHashLSH
from huggingface_hub import HfApi, hf_hub_download

from dedupe import cheap_norm, minhash
from fetch import card_licence

HERE = Path(__file__).resolve().parent
RAW_DIR = HERE / "data" / "raw"
PARA_MIN, PARA_MAX = 200, 1500
WIKI_DETOK = [(" @-@ ", "-"), (" @,@ ", ","), (" @.@ ", "."), (" ,", ","), (" .", "."), (" ;", ";"),
              (" :", ":"), (" )", ")"), ("( ", "("), (" 's", "'s"), (" n't", "n't"), ('" ', '"')]


def trigger_regex(words: list[str]) -> re.Pattern:
    return re.compile(r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b", re.IGNORECASE)


# ---------- per-kind candidate loaders: yield (text, split, group) ----------

def load_dolly(src: dict):
    for ex in load_dataset(src["hf_id"], split="train"):
        text = ex["instruction"].strip()
        ctx = (ex.get("context") or "").strip()
        if ctx and len(ctx) <= 600:
            text = f"{text}\n\n{ctx}"
        yield text, "train", ex.get("category") or "na"


def load_oasst(src: dict):
    for split in ("train", "validation"):
        for ex in load_dataset(src["hf_id"], split=split):
            if ex["role"] == "prompter" and not ex.get("deleted"):
                yield ex["text"].strip(), split, ex.get("lang") or "unk"


def load_tatoeba(src: dict):
    for pair in src["pairs"]:
        try:
            p = hf_hub_download(src["hf_id"], f"{pair}/test/0000.parquet", repo_type="dataset",
                                revision="refs/convert/parquet")
        except Exception as e:  # noqa: BLE001, a missing pair is reported, not fatal
            print(f"  tatoeba {pair}: {type(e).__name__}", file=sys.stderr)
            continue
        df = pd.read_parquet(p)
        for row in df.itertuples(index=False):
            if row.sourceLang == "eng":
                yield str(row.targetString).strip(), pair, row.targetlang
                if pair == "eng-fra":
                    yield str(row.sourceString).strip(), pair, "eng"
            else:
                yield str(row.sourceString).strip(), pair, row.sourceLang


def load_wikitext(src: dict):
    ds = load_dataset(src["hf_id"], src["config"], split="train", streaming=True)
    for i, ex in enumerate(ds):
        if i >= src["scan_lines"]:
            break
        line = ex["text"].strip()
        if not line or line.startswith("="):
            continue
        for a, b in WIKI_DETOK:
            line = line.replace(a, b)
        if PARA_MIN <= len(line) <= PARA_MAX:
            yield line, "train", "wiki"


def load_gutenberg(src: dict):
    ds = load_dataset(src["hf_id"], split="train", streaming=True)
    books = 0
    for ex in ds:
        if books >= src["scan_books"]:
            break
        meta = json.loads(ex["METADATA"]) if isinstance(ex["METADATA"], str) else ex["METADATA"]
        if meta.get("language") != "en":
            continue
        books += 1
        for para in re.split(r"\n\s*\n", ex["TEXT"]):
            para = re.sub(r"\s+", " ", para).strip()
            if not (PARA_MIN <= len(para) <= PARA_MAX) or "gutenberg" in para.lower():
                continue
            if sum(c.isupper() for c in para) > 0.3 * sum(c.isalpha() for c in para):
                continue
            yield para, "train", str(meta.get("text_id"))


LOADERS = {"dolly": load_dolly, "oasst": load_oasst, "tatoeba": load_tatoeba,
           "wikitext": load_wikitext, "gutenberg": load_gutenberg}


# ---------- selection ----------

def select(cands: list[dict], cap: int, rng: random.Random, stratify: bool) -> list[dict]:
    """Trigger rows first, then random fill. With stratify, quotas ∝ sqrt(group size)."""
    if not stratify:
        groups = {"all": cands}
        quotas = {"all": cap}
    else:
        groups = defaultdict(list)
        for c in cands:
            groups[c["group"]].append(c)
        w = {g: math.sqrt(len(v)) for g, v in groups.items()}
        tot = sum(w.values())
        quotas = {g: min(len(groups[g]), max(1, round(cap * w[g] / tot))) for g in groups}
    out = []
    for g, rows in groups.items():
        q = quotas[g]
        hard = [r for r in rows if r["trigger"]]
        soft = [r for r in rows if not r["trigger"]]
        rng.shuffle(hard)
        pick = hard[:q]
        if len(pick) < q:
            pick += rng.sample(soft, min(q - len(pick), len(soft)))
        out.extend(pick)
    rng.shuffle(out)
    return out[:cap]


def load_eval_lsh(cfg: dict, k: int, perms: int, thr: float) -> tuple[set[str], MinHashLSH]:
    exact: set[str] = set()
    lsh = MinHashLSH(threshold=thr, num_perm=perms)
    n = 0
    for ds in cfg["datasets"]:
        if ds["role"] != "eval":
            continue
        path = RAW_DIR / f"{ds['name']}.jsonl"
        if not path.exists():
            raise SystemExit(f"eval set {path} missing, run fetch.py first")
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                norm = cheap_norm(json.loads(line)["text"])
                if norm in exact:
                    continue
                exact.add(norm)
                lsh.insert(f"e{n}", minhash(norm, k, perms))
                n += 1
    return exact, lsh


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(HERE / "config.yaml"))
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    cfg = yaml.safe_load(Path(args.config).read_text())
    ben, dd = cfg["benign"], cfg["dedupe"]
    k, perms, thr = dd["shingle_words"], dd["minhash_perms"], dd["jaccard_threshold"]
    trig = trigger_regex(ben["trigger_words"])
    api = HfApi()
    warnings: list[str] = []
    eval_exact, eval_lsh = load_eval_lsh(cfg, k, perms, thr)
    summaries = []

    for src in ben["sources"]:
        if args.only and src["name"] not in args.only:
            continue
        name = src["name"]
        print(f"mining {src['hf_id']} ...", file=sys.stderr)
        s = {"name": name, "hf_id": src["hf_id"], "kind": src["kind"], "licence_card": None,
             "candidates": 0, "eval_collisions": 0, "rows": 0, "hard_negatives": 0, "groups": {}}
        lic, gated = card_licence(api, src["hf_id"], cfg["licence_allowlist"])
        s["licence_card"] = lic
        if lic not in cfg["licence_allowlist"]:
            msg = f"{src['hf_id']}: card licence {lic!r} not in allowlist"
            if not args.force:
                raise SystemExit(f"LICENCE FAIL: {msg} (use --force to override)")
            warnings.append(f"FORCED: {msg}")
        if lic != src.get("licence"):
            warnings.append(f"{src['hf_id']}: config says {src.get('licence')!r}, card says {lic!r}")

        seen: set[str] = set()
        cands: list[dict] = []
        for text, split, group in LOADERS[src["kind"]](src):
            if len(text) < ben["min_chars"]:
                continue
            norm = cheap_norm(text)
            if norm in seen:
                continue
            seen.add(norm)
            s["candidates"] += 1
            if norm in eval_exact or eval_lsh.query(minhash(norm, k, perms)):
                s["eval_collisions"] += 1
                continue
            cands.append({"text": text, "split": split, "group": group, "trigger": bool(trig.search(text))})

        rng = random.Random(cfg["seed"])
        rows = select(cands, src["cap"], rng, stratify=src["kind"] in ("oasst", "tatoeba"))
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        with (RAW_DIR / f"benign_{name}.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps({"text": r["text"], "label": 0, "source": f"benign_{name}",
                                     "split": r["split"]}, ensure_ascii=False) + "\n")
        s["rows"] = len(rows)
        s["hard_negatives"] = sum(r["trigger"] for r in rows)
        s["groups"] = dict(Counter(r["group"] for r in rows).most_common(20))
        summaries.append(s)

    print(f"\n{'name':<10} {'licence':<13} {'cands':>7} {'eval-hit':>8} {'rows':>6} {'hard-neg':>8}")
    for s in summaries:
        print(f"{s['name']:<10} {str(s['licence_card']):<13} {s['candidates']:>7} {s['eval_collisions']:>8} "
              f"{s['rows']:>6} {s['hard_negatives']:>8}")
    print(f"{'TOTAL':<10} {'':<13} {sum(s['candidates'] for s in summaries):>7} "
          f"{sum(s['eval_collisions'] for s in summaries):>8} {sum(s['rows'] for s in summaries):>6} "
          f"{sum(s['hard_negatives'] for s in summaries):>8}")
    for w in warnings:
        print(f"  ! {w}")
    out = RAW_DIR / "benign_summary.json"
    prev = json.loads(out.read_text())["sources"] if (args.only and out.exists()) else []
    done = {s["name"] for s in summaries}
    merged = [s for s in prev if s["name"] not in done] + summaries
    out.write_text(json.dumps({"sources": merged, "warnings": warnings}, indent=2))


if __name__ == "__main__":
    main()
