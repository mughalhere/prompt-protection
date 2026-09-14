#!/usr/bin/env python3
"""Eval-only sets: in_the_wild, NotInject, local attacks / benign-hard (never trained on)."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

import numpy as np
import yaml

from common import DATA, MODEL_DIR, dump_json, hashes_for, load_jsonl, matrix, metrics, predict_proba


def load_eval_sets(cfg: dict) -> dict[str, tuple[list[str], np.ndarray]]:
    sets: dict[str, tuple[list[str], np.ndarray]] = {}
    ev = load_jsonl(DATA / "dedupe" / "eval.jsonl")
    for ds in cfg["datasets"]:
        if ds["role"] != "eval":
            continue
        rows = [r for r in ev if r["source"] == ds["name"]]
        sets[ds["name"]] = ([r["text_normalized"] for r in rows], np.array([r["label"] for r in rows]))
    for name in ("local_attacks", "local_benign_hard"):
        p = DATA / "norm" / f"{name}.jsonl"
        if p.exists():
            rows = load_jsonl(p)
            sets[name] = ([r["text_normalized"] for r in rows], np.array([r["label"] for r in rows]))
    return sets


def model_weights(model: dict, quantized: bool) -> tuple[np.ndarray, float]:
    if quantized:
        q = np.frombuffer(base64.b64decode(model["weights_q_b64"]), dtype=np.int8).astype(np.float64)
        return q * model["scale"], model["bias"]
    return np.array(model["weights"], dtype=np.float64), model["bias"]


def evaluate_model(model: dict, cfg: dict, sets: dict, hashes: dict[str, list[np.ndarray]]) -> dict:
    thr = model["thresholds"]
    out: dict = {}
    for quantized in (False, True):
        w, b = model_weights(model, quantized)
        key = "quantized" if quantized else "float"
        out[key] = {}
        for name, (_, y) in sets.items():
            X = matrix(hashes[name], model["buckets"])
            p = predict_proba(X, w, b)
            out[key][name] = {t: metrics(y, p, thr[t]) for t in ("block", "flag")}
            out[key][name]["p50"] = metrics(y, p, 0.5)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(Path(__file__).with_name("config.yaml")))
    ap.add_argument("--model", default=str(MODEL_DIR / "model.json"))
    args = ap.parse_args()
    cfg = yaml.safe_load(Path(args.config).read_text())
    model = json.loads(Path(args.model).read_text())
    sets = load_eval_sets(cfg)
    hashes = {n: hashes_for(t, cfg["hyperparams"]["max_chars"], cache=f"eval_{n}") for n, (t, _) in sets.items()}
    res = evaluate_model(model, cfg, sets, hashes)
    dump_json(MODEL_DIR / "eval_only.json", res)
    for name in sets:
        m = res["quantized"][name]
        print(f"{name:<18} block: rec={m['block']['recall']:.3f} fpr={m['block']['fpr']:.4f} | "
              f"flag: rec={m['flag']['recall']:.3f} fpr={m['flag']['fpr']:.4f} | auroc={m['p50']['auroc']:.4f}")


if __name__ == "__main__":
    main()
