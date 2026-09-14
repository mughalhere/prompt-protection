#!/usr/bin/env python3
"""Train the embedded classifier: CV grid → LODO → final fit → thresholds → int8 quantisation.

Reads data/dedupe/train.jsonl (`text_normalized`), writes data/model/model_<buckets>.json,
data/model/model.json (the shipped variant) and data/model/metrics.json.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import yaml
from joblib import Parallel, delayed
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, train_test_split

from common import (DATA, MODEL_DIR, dump_json, hashes_for, load_jsonl, matrix, metrics, predict_proba,
                    quantize, reliability, threshold_for_fpr)
from evaluate import evaluate_model, load_eval_sets

warnings.filterwarnings("ignore", category=ConvergenceWarning)


def fit(X, y, C: float, l1_ratio: float, seed: int) -> LogisticRegression:
    clf = LogisticRegression(solver="saga", l1_ratio=l1_ratio, C=C,
                             class_weight="balanced", max_iter=2000, tol=1e-4, random_state=seed)
    clf.fit(X, y)
    return clf


def cv_score(X, y, C, l1, seed, folds):
    f1s = []
    for tr, te in folds:
        clf = fit(X[tr], y[tr], C, l1, seed)
        f1s.append(metrics(y[te], clf.predict_proba(X[te])[:, 1], 0.5)["f1"])
    return {"C": C, "l1_ratio": l1, "cv_f1": float(np.mean(f1s)), "cv_f1_std": float(np.std(f1s))}


def lodo(X, y, src: np.ndarray, sources: list[str], C, l1, seed, drop_only: set[str]) -> list[dict]:
    def one(s):
        held = src == s
        clf = fit(X[~held], y[~held], C, l1, seed)
        m = metrics(y[held], clf.predict_proba(X[held])[:, 1], 0.5)
        return {"source": s, "lodo_drop_only": s in drop_only, **m}
    return Parallel(n_jobs=-1)(delayed(one)(s) for s in sources)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(Path(__file__).with_name("config.yaml")))
    ap.add_argument("--quick", action="store_true", help="tiny grid / 3 folds for smoke tests")
    args = ap.parse_args()
    cfg = yaml.safe_load(Path(args.config).read_text())
    hp, seed = cfg["hyperparams"], cfg["seed"]
    t0 = time.time()

    rows = load_jsonl(DATA / "dedupe" / "train.jsonl")
    texts = [r["text_normalized"] for r in rows]
    y = np.array([r["label"] for r in rows])
    src = np.array([r["source"] for r in rows])
    sources = sorted(set(src))
    drop_only = {d["name"] for d in cfg["datasets"] if d.get("lodo_drop_only")}
    H = hashes_for(texts, hp["max_chars"], cache="train")
    fit_idx, val_idx = train_test_split(np.arange(len(y)), test_size=0.10, stratify=y, random_state=seed)
    print(f"train rows {len(y)} (pos {int(y.sum())}); fit {len(fit_idx)} / val {len(val_idx)}; "
          f"hashed in {time.time()-t0:.1f}s")

    eval_sets = load_eval_sets(cfg)
    eval_hashes = {n: hashes_for(t, hp["max_chars"], cache=f"eval_{n}") for n, (t, _) in eval_sets.items()}

    C_grid = hp["C_grid"][:2] if args.quick else hp["C_grid"]
    l1_grid = hp["l1_ratio_grid"][:2] if args.quick else hp["l1_ratio_grid"]
    n_folds = 3 if args.quick else 5
    results: dict = {"buckets": {}, "config": {"C_grid": C_grid, "l1_ratio_grid": l1_grid, "folds": n_folds,
                                                "seed": seed, "fit_rows": len(fit_idx), "val_rows": len(val_idx)}}

    for buckets in hp["buckets"]:
        tb = time.time()
        X = matrix(H, buckets)
        Xf, yf, sf = X[fit_idx], y[fit_idx], src[fit_idx]
        folds = list(StratifiedKFold(n_folds, shuffle=True, random_state=seed).split(Xf, yf))
        grid = Parallel(n_jobs=-1)(delayed(cv_score)(Xf, yf, C, l1, seed, folds)
                                   for C in C_grid for l1 in l1_grid)
        best = max(grid, key=lambda g: g["cv_f1"])
        print(f"[{buckets}] CV best C={best['C']} l1={best['l1_ratio']} F1={best['cv_f1']:.4f} "
              f"({time.time()-tb:.0f}s)")

        lodo_rows = lodo(Xf, yf, sf, sources, best["C"], best["l1_ratio"], seed, drop_only)
        headline = [r["f1"] for r in lodo_rows if r["pos"] >= 50 and not r["lodo_drop_only"]]
        lodo_f1 = float(np.mean(headline)) if headline else float("nan")
        print(f"[{buckets}] LODO headline F1 (sources with >=50 pos, excl. drop-only) = {lodo_f1:.4f}")

        clf = fit(Xf, yf, best["C"], best["l1_ratio"], seed)
        w, b = clf.coef_[0].astype(np.float64), float(clf.intercept_[0])
        nnz = int(np.count_nonzero(w))
        q, scale = quantize(w)
        wq = q.astype(np.float64) * scale

        Xv, yv = X[val_idx], y[val_idx]
        pv, pvq = predict_proba(Xv, w, b), predict_proba(Xv, wq, b)
        pb, pa = pvq[yv == 0], pvq[yv == 1]        # thresholds are set on the quantised model (what ships)
        block = threshold_for_fpr(pb, hp["fpr_targets"]["block"])
        flag = min(threshold_for_fpr(pb, hp["fpr_targets"]["flag"]), block)
        benign = float(np.percentile(pa, 1))
        thresholds = {"flag": flag, "block": block, "benign": benign}

        model = {"version": cfg.get("model_version", "3.0.0"), "buckets": buckets, "C": best["C"],
                 "l1_ratio": best["l1_ratio"], "bias": b, "scale": scale, "weights": w.tolist(),
                 "weights_q_b64": base64.b64encode(q.tobytes()).decode(), "thresholds": thresholds,
                 "max_chars": hp["max_chars"], "ngram_char": hp["ngram_char"], "ngram_word": hp["ngram_word"],
                 "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        (MODEL_DIR / f"model_{buckets}.json").write_text(json.dumps(model))

        ev = evaluate_model(model, cfg, eval_sets, eval_hashes)
        val = {"float": {t: metrics(yv, pv, thresholds[t]) for t in thresholds} | {"p50": metrics(yv, pv, 0.5)},
               "quantized": {t: metrics(yv, pvq, thresholds[t]) for t in thresholds} | {"p50": metrics(yv, pvq, 0.5)}}
        quant_delta = {
            "val_f1_p50_pp": 100 * (val["quantized"]["p50"]["f1"] - val["float"]["p50"]["f1"]),
            "in_the_wild_f1_block_pp": 100 * (ev["quantized"]["in_the_wild"]["block"]["f1"]
                                              - ev["float"]["in_the_wild"]["block"]["f1"]),
            "max_abs_prob_diff_val": float(np.abs(pv - pvq).max()),
        }
        gz_int8 = len(gzip.compress(q.tobytes(), 9))
        results["buckets"][str(buckets)] = {
            "cv_grid": grid, "best": best, "lodo": lodo_rows, "lodo_headline_f1": lodo_f1,
            "coef_nnz": nnz, "coef_total": int(w.size), "coef_max_abs": float(np.abs(w).max()),
            "scale": scale, "bias": b, "thresholds": thresholds, "validation": val,
            "reliability": reliability(yv, pvq), "eval_only": ev, "quant_delta_pp": quant_delta,
            "size": {"int8_raw": int(q.size), "int8_gz": gz_int8}, "seconds": time.time() - tb,
        }
        print(f"[{buckets}] nnz={nnz}/{w.size} int8 gz={gz_int8}B thresholds={thresholds} "
              f"quantΔ val F1 {quant_delta['val_f1_p50_pp']:+.3f}pp ({time.time()-tb:.0f}s)")

    small, big = str(hp["buckets"][0]), str(hp["buckets"][-1])
    gain = 100 * (results["buckets"][big]["lodo_headline_f1"] - results["buckets"][small]["lodo_headline_f1"])
    ship = big if (gain >= 1.0 and results["buckets"][big]["size"]["int8_gz"] <= 80 * 1024) else small
    results["selection"] = {"shipped_buckets": int(ship), "lodo_gain_pp_big_vs_small": gain,
                            "rule": ">=1.0 pp LODO-F1 gain AND <=80 KB gz int8, else smallest"}
    (MODEL_DIR / "model.json").write_text((MODEL_DIR / f"model_{ship}.json").read_text())
    results["total_seconds"] = time.time() - t0
    dump_json(MODEL_DIR / "metrics.json", results)
    print(f"shipped buckets={ship} (gain {gain:+.2f} pp); total {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
