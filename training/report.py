#!/usr/bin/env python3
"""Render training/REPORT.md from data/model/metrics.json (+ export sizes, DATA_REPORT.md)."""
from __future__ import annotations

import json
import math
from pathlib import Path

from common import MODEL_DIR

HERE = Path(__file__).resolve().parent


def f(x, d=4):
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.{d}f}"


def pct(x):
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{100*x:.2f}%"


def main() -> None:
    m = json.loads((MODEL_DIR / "metrics.json").read_text())
    sizes = json.loads((MODEL_DIR / "export_sizes.json").read_text()) if (MODEL_DIR / "export_sizes.json").exists() else {}
    ship = str(m["selection"]["shipped_buckets"])
    L = []
    L.append("# Training report, prompt-protection v3 embedded classifier\n")
    L.append(f"Shipped: **{ship} buckets**, dense int8 (`src/ml/weights.ts`). "
             f"Selection rule: {m['selection']['rule']}; measured gain of {m['config']} ")
    L[-1] = (f"Shipped: **{ship} buckets**, dense int8 (`src/ml/weights.ts`). Selection rule: "
             f"{m['selection']['rule']}; measured LODO-F1 gain big vs small = "
             f"{m['selection']['lodo_gain_pp_big_vs_small']:+.2f} pp.\n")
    c = m["config"]
    L.append(f"Model: `LogisticRegression(saga, elasticnet, class_weight=balanced)`, seed {c['seed']}, "
             f"{c['folds']}-fold stratified CV over C ∈ {c['C_grid']} × l1_ratio ∈ {c['l1_ratio_grid']}; "
             f"fit rows {c['fit_rows']}, validation pool {c['val_rows']} (stratified 10%, held out of the final fit).\n")

    L.append("## Per-bucket summary\n")
    L.append("| buckets | best C | best l1_ratio | CV F1@0.5 | LODO headline F1 | coef nnz | int8 gz | thresholds (flag / block / benign) | quant Δ val F1 (pp) | quant Δ in_the_wild F1@block (pp) | max |Δp| |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for b, r in m["buckets"].items():
        t = r["thresholds"]; qd = r["quant_delta_pp"]
        L.append(f"| {b}{' **(shipped)**' if b == ship else ''} | {r['best']['C']} | {r['best']['l1_ratio']} | "
                 f"{f(r['best']['cv_f1'])} ± {f(r['best']['cv_f1_std'],3)} | {f(r['lodo_headline_f1'])} | "
                 f"{r['coef_nnz']}/{r['coef_total']} | {r['size']['int8_gz']} B | "
                 f"{f(t['flag'])} / {f(t['block'])} / {f(t['benign'])} | {qd['val_f1_p50_pp']:+.3f} | "
                 f"{qd['in_the_wild_f1_block_pp']:+.3f} | {f(qd['max_abs_prob_diff_val'],5)} |")
    if sizes:
        L.append(f"\nExport sizes: `weights.ts` {sizes['weights_ts_bytes']} B ({sizes['weights_ts_gz']} B gz); "
                 f"raw int8 {sizes['int8_raw']} B ({sizes['int8_gz']} B gz).\n")

    for b, r in m["buckets"].items():
        L.append(f"\n## buckets = {b}{' (shipped)' if b == ship else ''}\n")
        L.append("### CV grid (mean F1@0.5, 5-fold)\n")
        L.append("| C \\ l1_ratio | " + " | ".join(str(l) for l in c["l1_ratio_grid"]) + " |")
        L.append("|---|" + "---|" * len(c["l1_ratio_grid"]))
        for C in c["C_grid"]:
            row = [next(g for g in r["cv_grid"] if g["C"] == C and g["l1_ratio"] == l)["cv_f1"] for l in c["l1_ratio_grid"]]
            L.append(f"| {C} | " + " | ".join(f(x) for x in row) + " |")
        L.append("\n### Leave-one-dataset-out (fit on all other train sources, score the held-out one at p=0.5)\n")
        L.append("| source | N | pos | recall | precision | F1 | FPR | AUROC | note |")
        L.append("|---|---|---|---|---|---|---|---|---|")
        for x in r["lodo"]:
            note = "drop-only: labels relative to a paired system prompt; reported separately, not in headline" if x["lodo_drop_only"] else ("benign-only source: FPR is the number" if x["pos"] == 0 else ("<50 pos: excluded from headline" if x["pos"] < 50 else ""))
            L.append(f"| {x['source']} | {x['n']} | {x['pos']} | {f(x['recall'])} | {f(x['precision'])} | {f(x['f1'])} | {pct(x['fpr'])} | {f(x['auroc'])} | {note} |")
        L.append(f"\nHeadline LODO F1 (mean over sources with ≥50 positives, excluding drop-only): **{f(r['lodo_headline_f1'])}**\n")

        L.append("### Validation pool (10% held out; thresholds chosen here on the quantised model)\n")
        L.append("| model | threshold | p | recall | precision | F1 | FPR | AUROC |")
        L.append("|---|---|---|---|---|---|---|---|")
        for kind in ("float", "quantized"):
            for t in ("flag", "block", "benign", "p50"):
                x = r["validation"][kind][t]
                L.append(f"| {kind} | {t} | {f(x['threshold'])} | {f(x['recall'])} | {f(x['precision'])} | {f(x['f1'])} | {pct(x['fpr'])} | {f(x['auroc'])} |")
        L.append("\n### Reliability (quantised, validation pool, 10 equal-width bins)\n")
        L.append("| bin | n | mean predicted | observed positive rate |")
        L.append("|---|---|---|---|")
        for x in r["reliability"]:
            L.append(f"| {x['bin']} | {x['n']} | {f(x['mean_pred'],3)} | {f(x['obs_pos'],3)} |")

        L.append("\n### Eval-only sets (never trained on; quantised model unless noted)\n")
        L.append("| set | N | pos | @block: recall | @block: precision | @block: FPR | @block: F1 | @flag: recall | @flag: FPR | @flag: F1 | AUROC | float @block F1 |")
        L.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for name, x in r["eval_only"]["quantized"].items():
            fl = r["eval_only"]["float"][name]
            bl, fg, p5 = x["block"], x["flag"], x["p50"]
            L.append(f"| {name} | {bl['n']} | {bl['pos']} | {f(bl['recall'])} | {f(bl['precision'])} | {pct(bl['fpr'])} | {f(bl['f1'])} | "
                     f"{f(fg['recall'])} | {pct(fg['fpr'])} | {f(fg['f1'])} | {f(p5['auroc'])} | {f(fl['block']['f1'])} |")
        ni = r["eval_only"]["quantized"].get("notinject")
        if ni:
            L.append(f"\nNotInject over-defence accuracy (1 − FPR): **{pct(1-ni['block']['fpr'])} at block**, "
                     f"**{pct(1-ni['flag']['fpr'])} at flag**.\n")

    L.append("\n## Data\n\nSee `DATA_REPORT.md` (dataset table, licences, dedupe, benign mining). "
             "Feature scheme mirrors `src/ml/features.ts` exactly (verified on 16 parity strings incl. surrogates and truncation); "
             "`tests/ml/__fixtures__/golden.json` carries 64 golden vectors.\n")
    (HERE / "REPORT.md").write_text("\n".join(L) + "\n")
    print(f"wrote {HERE / 'REPORT.md'}")


if __name__ == "__main__":
    main()
