"""Shared helpers for train/evaluate/export: data loading, hash cache, metrics."""
from __future__ import annotations

import json
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.metrics import roc_auc_score

from features import build_matrix, gram_hashes

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
MODEL_DIR = DATA / "model"
FEAT_DIR = DATA / "feat"


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _hash_one(args: tuple[str, int]) -> np.ndarray:
    return gram_hashes(args[0], args[1])


def hashes_for(texts: list[str], max_chars: int, cache: str | None = None) -> list[np.ndarray]:
    """Bucket-independent gram hashes per row; cached under data/feat/<cache>.npz."""
    path = FEAT_DIR / f"{cache}.npz" if cache else None
    if path and path.exists():
        z = np.load(path)
        if int(z["n"]) == len(texts) and int(z["max_chars"]) == max_chars:
            flat, off = z["flat"], z["off"]
            return [flat[off[i]:off[i + 1]] for i in range(len(texts))]
    with Pool() as pool:
        rows = pool.map(_hash_one, [(t, max_chars) for t in texts], chunksize=256)
    if path:
        FEAT_DIR.mkdir(parents=True, exist_ok=True)
        off = np.cumsum([0] + [r.size for r in rows])
        np.savez(path, flat=np.concatenate(rows) if rows else np.empty(0, np.uint32), off=off,
                 n=len(texts), max_chars=max_chars)
    return rows


def matrix(hashes: list[np.ndarray], buckets: int) -> csr_matrix:
    return build_matrix(hashes, buckets)


def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-z))


def predict_proba(X: csr_matrix, w: np.ndarray, b: float) -> np.ndarray:
    return sigmoid(X @ w + b)


def quantize(w: np.ndarray) -> tuple[np.ndarray, float]:
    scale = float(np.abs(w).max() / 127.0) or 1.0
    q = np.clip(np.round(w / scale), -127, 127).astype(np.int8)
    return q, scale


def metrics(y: np.ndarray, p: np.ndarray, thr: float = 0.5) -> dict:
    y = np.asarray(y).astype(int)
    pred = (p >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    pos, neg = tp + fn, fp + tn
    rec = tp / pos if pos else float("nan")
    prec = tp / (tp + fp) if (tp + fp) else (float("nan") if pos else float("nan"))
    f1 = 2 * prec * rec / (prec + rec) if pos and (tp + fp) and (prec + rec) else (0.0 if pos else float("nan"))
    fpr = fp / neg if neg else float("nan")
    auroc = float(roc_auc_score(y, p)) if pos and neg else float("nan")
    return {"n": int(len(y)), "pos": int(pos), "neg": int(neg), "threshold": float(thr), "recall": rec,
            "precision": prec, "f1": f1, "fpr": fpr, "accuracy": (tp + tn) / len(y) if len(y) else float("nan"),
            "auroc": auroc}


def threshold_for_fpr(p_benign: np.ndarray, fpr: float) -> float:
    """Smallest p such that the share of benign rows with prob >= p is <= fpr."""
    if p_benign.size == 0:
        return 0.5
    allowed = int(np.floor(fpr * p_benign.size))
    s = np.sort(p_benign)[::-1]
    if allowed >= s.size:
        return 0.0
    return float(min(1.0, np.nextafter(s[allowed], 1.0)))


def reliability(y: np.ndarray, p: np.ndarray, bins: int = 10) -> list[dict]:
    edges = np.linspace(0, 1, bins + 1)
    out = []
    for i in range(bins):
        m = (p >= edges[i]) & ((p < edges[i + 1]) if i < bins - 1 else (p <= edges[i + 1]))
        n = int(m.sum())
        out.append({"bin": f"[{edges[i]:.1f},{edges[i+1]:.1f}{']' if i == bins-1 else ')'}", "n": n,
                    "mean_pred": float(p[m].mean()) if n else float("nan"),
                    "obs_pos": float(y[m].mean()) if n else float("nan")})
    return out


def dump_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=_np))


def _np(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(type(o))
