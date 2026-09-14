# External evaluation samples

Committed verbatim samples of public datasets, used only for evaluation (never for training).

| File | Source | Licence | Rows |
|---|---|---|---|
| `notinject.jsonl` | [leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject) — over-defence benchmark, all benign | MIT | 339 (all three splits) |
| `in_the_wild.jsonl` | [TrustAIRLab/in-the-wild-jailbreak-prompts](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts) (`jailbreak_2023_12_25` + `regular_2023_12_25`) | MIT | 900 seeded sample (300 jailbreak / 600 regular) |

Refresh with `training/fetch.py` and re-sample with `bench/fetch-external.mjs`; the seed is 42.
