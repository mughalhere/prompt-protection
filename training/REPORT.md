# Training report, prompt-protection v3 embedded classifier

Shipped: **65536 buckets**, dense int8 (`src/ml/weights.ts`). Selection rule: >=1.0 pp LODO-F1 gain AND <=80 KB gz int8, else smallest; measured LODO-F1 gain big vs small = +0.00 pp.

Model: `LogisticRegression(saga, elasticnet, class_weight=balanced)`, seed 42, 5-fold stratified CV over C ∈ [0.05, 0.1, 0.25, 0.5, 1.0, 2.0] × l1_ratio ∈ [0.0, 0.15, 0.5, 0.85, 1.0]; fit rows 31842, validation pool 3539 (stratified 10%, held out of the final fit).

## Per-bucket summary

| buckets | best C | best l1_ratio | CV F1@0.5 | LODO headline F1 | coef nnz | int8 gz | thresholds (flag / block / benign) | quant Δ val F1 (pp) | quant Δ in_the_wild F1@block (pp) | max |Δp| |
|---|---|---|---|---|---|---|---|---|---|---|
| 65536 **(shipped)** | 2.0 | 0.0 | 0.9808 ± 0.002 | 0.5307 | 65536/65536 | 33696 B | 0.3779 / 0.6220 / 0.1951 | +0.032 | +0.094 | 0.01168 |

Export sizes: `weights.ts` 87994 B (41364 B gz); raw int8 65536 B (33696 B gz).


## buckets = 65536 (shipped)

### CV grid (mean F1@0.5, 5-fold)

| C \ l1_ratio | 0.0 | 0.15 | 0.5 | 0.85 | 1.0 |
|---|---|---|---|---|---|
| 0.05 | 0.9529 | 0.9364 | 0.9192 | 0.8866 | 0.8809 |
| 0.1 | 0.9600 | 0.9497 | 0.9378 | 0.9337 | 0.9302 |
| 0.25 | 0.9680 | 0.9634 | 0.9550 | 0.9524 | 0.9506 |
| 0.5 | 0.9729 | 0.9699 | 0.9665 | 0.9645 | 0.9640 |
| 1.0 | 0.9773 | 0.9754 | 0.9733 | 0.9724 | 0.9716 |
| 2.0 | 0.9808 | 0.9791 | 0.9777 | 0.9773 | 0.9764 |

### Leave-one-dataset-out (fit on all other train sources, score the held-out one at p=0.5)

| source | N | pos | recall | precision | F1 | FPR | AUROC | note |
|---|---|---|---|---|---|---|---|---|
| benign_dolly | 5367 | 0 |, | 0.0000 |, | 0.41% |, | benign-only source: FPR is the number |
| benign_gutenberg | 1356 | 0 |, | 0.0000 |, | 1.03% |, | benign-only source: FPR is the number |
| benign_oasst | 4358 | 0 |, | 0.0000 |, | 3.12% |, | benign-only source: FPR is the number |
| benign_tatoeba | 2254 | 0 |, | 0.0000 |, | 0.53% |, | benign-only source: FPR is the number |
| benign_wikitext | 2234 | 0 |, | 0.0000 |, | 0.04% |, | benign-only source: FPR is the number |
| deepset | 574 | 210 | 0.1381 | 0.9667 | 0.2417 | 0.27% | 0.7635 |  |
| gandalf | 892 | 892 | 0.8969 | 1.0000 | 0.9456 |, |, |  |
| hackaprompt | 7070 | 7070 | 0.2537 | 1.0000 | 0.4048 |, |, |  |
| jackhhao | 572 | 1 | 1.0000 | 0.0185 | 0.0364 | 9.28% | 0.9650 | <50 pos: excluded from headline |
| spml | 7165 | 5624 | 0.1353 | 0.9896 | 0.2381 | 0.52% | 0.7263 | drop-only: labels relative to a paired system prompt; reported separately, not in headline |

Headline LODO F1 (mean over sources with ≥50 positives, excluding drop-only): **0.5307**

### Validation pool (10% held out; thresholds chosen here on the quantised model)

| model | threshold | p | recall | precision | F1 | FPR | AUROC |
|---|---|---|---|---|---|---|---|
| float | flag | 0.3779 | 0.9739 | 0.9739 | 0.9739 | 1.99% | 0.9981 |
| float | block | 0.6220 | 0.9537 | 0.9925 | 0.9727 | 0.55% | 0.9981 |
| float | benign | 0.1951 | 0.9902 | 0.9411 | 0.9650 | 4.74% | 0.9981 |
| float | p50 | 0.5000 | 0.9648 | 0.9853 | 0.9750 | 1.10% | 0.9981 |
| quantized | flag | 0.3779 | 0.9739 | 0.9739 | 0.9739 | 1.99% | 0.9981 |
| quantized | block | 0.6220 | 0.9537 | 0.9932 | 0.9730 | 0.50% | 0.9981 |
| quantized | benign | 0.1951 | 0.9896 | 0.9405 | 0.9644 | 4.79% | 0.9981 |
| quantized | p50 | 0.5000 | 0.9648 | 0.9860 | 0.9753 | 1.05% | 0.9981 |

### Reliability (quantised, validation pool, 10 equal-width bins)

| bin | n | mean predicted | observed positive rate |
|---|---|---|---|
| [0.0,0.1) | 1797 | 0.023 | 0.003 |
| [0.1,0.2) | 134 | 0.139 | 0.090 |
| [0.2,0.3) | 59 | 0.249 | 0.288 |
| [0.3,0.4) | 23 | 0.355 | 0.391 |
| [0.4,0.5) | 26 | 0.444 | 0.385 |
| [0.5,0.6) | 26 | 0.557 | 0.615 |
| [0.6,0.7) | 25 | 0.650 | 0.800 |
| [0.7,0.8) | 28 | 0.750 | 0.857 |
| [0.8,0.9) | 60 | 0.853 | 1.000 |
| [0.9,1.0] | 1361 | 0.988 | 0.999 |

### Eval-only sets (never trained on; quantised model unless noted)

| set | N | pos | @block: recall | @block: precision | @block: FPR | @block: F1 | @flag: recall | @flag: FPR | @flag: F1 | AUROC | float @block F1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| in_the_wild | 14477 | 1356 | 0.4963 | 0.1732 | 24.48% | 0.2568 | 0.7087 | 46.85% | 0.2271 | 0.6660 | 0.2559 |
| notinject | 339 | 0 |, | 0.0000 | 7.67% |, |, | 20.35% |, |, |, |
| local_attacks | 130 | 130 | 0.1923 | 1.0000 |, | 0.3226 | 0.3308 |, | 0.4971 |, | 0.3226 |
| local_benign_hard | 155 | 0 |, | 0.0000 | 8.39% |, |, | 14.84% |, |, |, |

NotInject over-defence accuracy (1 − FPR): **92.33% at block**, **79.65% at flag**.


## Data

See `DATA_REPORT.md` (dataset table, licences, dedupe, benign mining). Feature scheme mirrors `src/ml/features.ts` exactly (verified on 16 parity strings incl. surrogates and truncation); `tests/ml/__fixtures__/golden.json` carries 64 golden vectors.

