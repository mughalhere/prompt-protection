"""Python mirror of src/ml/features.ts + src/ml/hash.ts + src/utils/hash.ts.

All hashing runs over UTF-16 code units so surrogate pairs, truncation and
char n-grams behave exactly as in JS. FNV-1a is vectorised with numpy over
2-D arrays of code units grouped by gram length.
"""
from __future__ import annotations

import numpy as np
from scipy.sparse import csr_matrix

FNV_OFFSET = np.uint32(0x811C9DC5)
FNV_PRIME = np.uint32(0x01000193)
CHAR_FAMILIES = (("c3", 3), ("c4", 4), ("c5", 5))
FAMILY_SEP = 1
SPACE = 32
ALNUM = np.zeros(65536, dtype=bool)
ALNUM[ord("0"):ord("9") + 1] = True
ALNUM[ord("a"):ord("z") + 1] = True


def code_units(text: str) -> np.ndarray:
    return np.frombuffer(text.encode("utf-16-le"), dtype="<u2").astype(np.uint32)


def fnv1a32_rows(mat: np.ndarray) -> np.ndarray:
    """FNV-1a over each row of a (rows × units) uint32 matrix."""
    h = np.full(mat.shape[0], FNV_OFFSET, dtype=np.uint32)
    with np.errstate(over="ignore"):
        for j in range(mat.shape[1]):
            h = (h ^ mat[:, j]) * FNV_PRIME
    return h


def fnv1a32(text: str) -> int:
    return int(fnv1a32_rows(code_units(text)[None, :])[0]) if text else int(FNV_OFFSET)


def _prefix(family: str) -> np.ndarray:
    return np.array([ord(c) for c in family] + [FAMILY_SEP], dtype=np.uint32)


def _tokens(units: np.ndarray) -> list[np.ndarray]:
    """tokenize(): split on runs of non-[a-z0-9] code units, drop empties."""
    mask = ALNUM[units]
    if not mask.any():
        return []
    edges = np.flatnonzero(np.diff(np.concatenate(([0], mask.view(np.int8), [0]))))
    return [units[s:e] for s, e in zip(edges[::2], edges[1::2])]


def gram_hashes(text: str, max_chars: int = 4000) -> np.ndarray:
    """Unique 32-bit FNV hashes of every family-salted gram (bucket-independent)."""
    units = code_units(text)[:max_chars]
    if units.size == 0:
        return np.empty(0, dtype=np.uint32)
    out = []
    padded = np.concatenate(([SPACE], units, [SPACE])).astype(np.uint32)
    for family, n in CHAR_FAMILIES:
        if padded.size < n:
            continue
        win = np.lib.stride_tricks.sliding_window_view(padded, n)
        pre = np.broadcast_to(_prefix(family), (win.shape[0], len(family) + 1))
        out.append(fnv1a32_rows(np.hstack((pre, win))))
    words = _tokens(units)
    grams: dict[int, list[np.ndarray]] = {}
    for i, w in enumerate(words):
        g = np.concatenate((_prefix("w1"), w))
        grams.setdefault(g.size, []).append(g)
        if i + 1 < len(words):
            g2 = np.concatenate((_prefix("w2"), w, [SPACE], words[i + 1]))
            grams.setdefault(g2.size, []).append(g2)
    for rows in grams.values():
        out.append(fnv1a32_rows(np.vstack(rows)))
    return np.unique(np.concatenate(out))


def keys_from_hashes(h: np.ndarray, buckets: int) -> np.ndarray:
    """Unique sorted keys = bucket*2 + (sign<0), matching featurize() ordering."""
    if h.size == 0:
        return np.empty(0, dtype=np.int64)
    sign_neg = (h >> np.uint32(16)) & np.uint32(1)
    return np.unique((h % np.uint32(buckets)).astype(np.int64) * 2 + sign_neg.astype(np.int64))


def featurize(text: str, buckets: int = 65536, max_chars: int = 4000) -> list[tuple[int, int]]:
    """[(bucket, sign)] in JS featurize() order: bucket asc, then +1 before −1."""
    keys = keys_from_hashes(gram_hashes(text, max_chars), buckets)
    return [(int(k >> 1), -1 if k & 1 else 1) for k in keys]


def build_matrix(hash_rows: list[np.ndarray], buckets: int) -> csr_matrix:
    """Rows of sign/sqrt(nnz), the l2-normalised binary vector the runtime scores."""
    indptr = [0]
    indices, data = [], []
    for h in hash_rows:
        keys = keys_from_hashes(h, buckets)
        nnz = keys.size
        if nnz:
            indices.append(keys >> 1)
            data.append(np.where(keys & 1, -1.0, 1.0) / np.sqrt(nnz))
        indptr.append(indptr[-1] + nnz)
    ind = np.concatenate(indices) if indices else np.empty(0, dtype=np.int64)
    dat = np.concatenate(data) if data else np.empty(0, dtype=np.float64)
    return csr_matrix((dat, ind, np.array(indptr)), shape=(len(hash_rows), buckets))
