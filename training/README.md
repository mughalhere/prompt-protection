# training/

Python pipeline for the embedded ML classifier (plan §E). Nothing here ships in the npm
package; only `REPORT.md`, `config.yaml`, the exported `weights.ts` and `golden.json` are committed.

## Pipeline

```
make venv      # python3 -m venv .venv + pinned requirements.txt (Python 3.13)
make fetch     # HF datasets → data/raw/<name>.jsonl  {text,label,source,split}
make mine-benign # licence-clean benign rows → data/raw/benign_<name>.jsonl (trigger-word rows first)
make normalize # real JS normalizer (dist/lite.js) → data/norm/*.jsonl (+ local datasets/ sets)
make dedupe    # exact + MinHash(word-5, 128 perms, J≥0.8) on text_normalized → data/dedupe/{train,eval}.jsonl
make fit       # CV grid → LODO → final fit → thresholds → int8 → data/model/{model,metrics}.json
make eval      # eval-only sets (in_the_wild, NotInject, datasets/attacks + benign-hard)
make export    # → src/ml/weights.ts (dense int8, base64; prints gz sizes)
make golden    # → tests/ml/__fixtures__/golden.json (64 JS/Python parity vectors)
make report    # → REPORT.md
make train     # the whole chain above
```

`data/` and `.venv/` are gitignored; every step is reproducible from `config.yaml` (seed 42).
`DATA_REPORT.md` summarises the corpus, `REPORT.md` the model. `features.py` mirrors
`src/ml/features.ts` bit-for-bit (FNV-1a over UTF-16 code units, family-salted buckets, alternate
sign); Python only ever featurizes `text_normalized` produced by the JS `normalize()`.

## Licence policy

`fetch.py` / `mine_benign.py` read the licence from each Hugging Face dataset card at fetch time
and **hard-fail** unless it is in `licence_allowlist` (`config.yaml`: apache-2.0, mit, cc-by-4.0,
cc-by-sa-4.0, cc-by-sa-3.0, cc-by-2.0, cc0-1.0, bsd-3-clause). `--force` lets a failing dataset
through with a warning in `data/raw/*_summary.json`. No-licence, non-commercial, or leaking
datasets are listed under `excluded:` and never downloaded. Gated `hackaprompt/hackaprompt-dataset`
needs `hf auth login` (or `HF_TOKEN`); without a token `make fetch` skips it with a warning.

## Train / eval separation, benign mining

Eval sets (`role: eval`: in-the-wild, NotInject; plus `datasets/`) never enter train; `dedupe.py` and
`mine_benign.py` drop any train candidate that is an exact/MinHash near-duplicate of an eval row.
Benign rows come from dolly, oasst1, tatoeba_mt, wikitext-103, Gutenberg — trigger-word rows first.
