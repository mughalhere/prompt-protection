# Data report, prompt-protection v3 training corpus

Generated 2026-09-14 by `make fetch mine-benign dedupe` (seed 42). Licences verified live from the
Hugging Face dataset card (`HfApi.dataset_info(...).card_data.license`; for a licence list the first
allowlisted entry is recorded). Raw numbers: `data/raw/fetch_summary.json`, `data/raw/benign_summary.json`,
`data/dedupe/stats.json` (gitignored, reproducible).

## Labelled datasets

| name | hf_id | licence (card) | role | rows before cap | after cap | pos / neg | exact | near (in-train) | cross-split | final rows | final pos / neg | notes |
|---|---|---|---|---:|---:|---|---:|---:|---:|---:|---|---|
| deepset | deepset/prompt-injections | apache-2.0 | train | 662 | 662 | 263 / 399 | 0 | 11 | 11 | 640 | 241 / 399 | |
| jackhhao | jackhhao/jailbreak-classification | apache-2.0 | train | 1306 | 1306 | 666 / 640 | 20 | 0 | **647** | 639 | **1 / 638** | jailbreak half ≈ in_the_wild (finding 1) |
| gandalf | Lakera/gandalf_ignore_instructions | mit | train | 1000 | 1000 | 1000 / 0 | 1 | 0 | 0 | 999 | 999 / 0 | all three splits, all attacks |
| spml | reshabhs/SPML_Chatbot_Prompt_Injection | mit | train | 16011 | 8000 (stratified) | 6266 / 1734 | 21 | 6 | 0 | 7973 | 6262 / 1711 | `lodo_drop_only: true`, labels are relative to a paired system prompt; many positives read benign standalone. In the final fit, LODO fold reported separately. |
| in_the_wild | TrustAIRLab/in-the-wild-jailbreak-prompts (`jailbreak_2023_12_25` + `regular_2023_12_25`) | mit | eval | 15140 | 15140 | 1405 / 13735 | 662 |, |, | 14478 | 1356 / 13122 | |
| notinject | leolee99/NotInject (three splits) | mit | eval | 339 | 339 | 0 / 339 | 0 |, |, | 339 | 0 / 339 | over-defence set, eval only |

## Mined benign (all label 0, role train), `mine_benign.py`

Selection: rows containing ≥1 trigger word (ignore, instruction(s), override, cancel, system, prompt, forget,
disregard, pretend, act as, role, bypass, reveal, secret, password, admin, developer mode, jailbreak, rules)
are taken first, then the cap is filled at random. Every candidate is checked against the eval sets
(exact + MinHash) before selection. oasst/tatoeba quotas ∝ √(rows per language) so minority languages are kept.

| name | hf_id | licence (card) | what | candidates | eval collisions | rows | hard negatives (≥1 trigger word) | dedupe drops | final rows |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| benign_dolly | databricks/databricks-dolly-15k | cc-by-sa-3.0 | `instruction` (+ `context` when ≤ 600 chars) | 14657 | 1 | 6000 | 230 | 20 | 5980 |
| benign_oasst | OpenAssistant/oasst1 | apache-2.0 | `role == prompter`, train+validation, all langs | 31195 | 12 | 4825 | 586 | 1 | 4824 |
| benign_tatoeba | Helsinki-NLP/tatoeba_mt (`refs/convert/parquet`) | cc-by-2.0 | non-English side of 16 eng-* test pairs + eng from eng-fra | 132533 | 0 | 2499 | 115 | 0 | 2499 |
| benign_wikitext | Salesforce/wikitext `wikitext-103-raw-v1` | cc-by-sa-3.0 (card: [cc-by-sa-3.0, gfdl]) | paragraphs 200–1500 chars, first 300k lines, light detok | 111916 | 0 | 2500 | 2500 | 1 | 2499 |
| benign_gutenberg | sedthh/gutenberg_english | mit | paragraphs 200–1500 chars from first 600 streamed `en` books | 26865 | 0 | 1500 | 1147 | 0 | 1500 |
| **total** | | | | 317166 | 13 | 17324 | 4578 | 22 | 17302 |

**Hard-negative count in final train: 4,701 benign rows contain ≥1 trigger word** (4,573 mined + 128 from
deepset/jackhhao/spml negatives) = 23% of all negatives. Dominant words: `system` (wiki 1039, gutenberg 363,
oasst 192), `role` (wiki 815), `secret` (gutenberg 300), `prompt` (oasst 124), `act as` (oasst 43, wiki 50),
`pretend` (gutenberg 40, oasst 33), `password` (oasst 21). Every wikitext pick is trigger-bearing because
111k candidates contained far more than 2,500 such paragraphs, by design (oversample), noted for LODO.

Language spread: oasst (top): en 1199, es 852, ru 539, de 340, fr 310, zh 278, th 237, pt-BR 200, ca 188, uk 165,
it 125, pl 100, ja 94 (+7 more). tatoeba: rus 230, ita 221, por 194, fra 191, nld 186, eng 183, fin 172, swe 168,
pol 168, ara 155, hin 115, ind 107, urd 67, kor 60, cmn_Hans 50, cmn_Hant 44, jpn 43 (+ arq, yue, arz).

## Totals after dedupe

| split | rows | pos | neg | pos share |
|---|---:|---:|---:|---:|
| train (before benign mining) | 10,251 | 7,503 | 2,748 | 73% |
| **train (after benign mining)** | **27,553** | **7,503** | **20,050** | **27%** |
| eval | 14,817 | 1,356 | 13,461 | 9% |

Dedupe: exact 705 · in-train MinHash 38 · cross-split 658 (deepset 11, jackhhao 647). Method: exact on
lowercase+whitespace-collapsed text, then MinHash LSH (word 5-shingles, 128 perms, Jaccard ≥ 0.8); eval rows
are inserted first so any train row colliding with an eval row is dropped from train, never from eval.

## Not fetched / excluded

| hf_id | licence (card) | status | why |
|---|---|---|---|
| hackaprompt/hackaprompt-dataset | mit | **skipped** (config kept, cap 50000) | HF `gated: auto`, needs an HF token; none in env / `~/.cache/huggingface/token`. `hf auth login` then `make fetch` includes it (label = `correct == true`, no benign rows). |
| xTRam1/safe-guard-prompt-injection | none | excluded | seeded from jackhhao → train leakage; no licence on card |
| JasperLS/prompt-injections | none | excluded | no licence; identical row/label counts to deepset (546/116, 343/203), it is the deepset upstream copy |
| qualifire/prompt-injections-benchmark | cc-by-nc-4.0 | excluded | non-commercial licence fails allowlist; also gated |
| Deysi/prompt-injection |, | excluded | repo not found (401/404 from `dataset_info`, 2026-09-14) |
| Helsinki-NLP/tatoeba, tatoeba, deepmind/pg19 | cc-by-2.0 / apache-2.0 | not usable | script-based datasets (`datasets` ≥ 4 refuses loading scripts); pg19 has no parquet convert. tatoeba_mt's parquet convert used instead. |
| manu/project_gutenberg | none | excluded | no licence field on card |
| Helsinki-NLP/opus-100 | unknown | excluded | licence `unknown` |

## Findings worth acting on

1. **jackhhao jailbreaks ≈ in-the-wild jailbreaks.** 647 of 666 jackhhao positives are near-duplicates (Jaccard ≥ 0.8)
   of TrustAIRLab eval rows: both scraped from the same DAN/jailbreak community posts. After cross-split removal
   jackhhao contributes 1 positive; its benign half is kept. in_the_wild is therefore a genuinely held-out set.
2. **Class balance now 27% positive** (was 73%). The 20,050 negatives span imperative instructions (dolly), chat
   prompts in ~30 languages (oasst), short multilingual sentences (tatoeba), encyclopaedic and fiction prose.
3. **spml caveat** (`lodo_drop_only`): labels depend on a paired system prompt; the LODO fold that drops spml is the
   honest generalisation number for that source.
4. **Tatoeba pair coverage gap:** the parquet convert has no `eng-spa`, `eng-deu`, `eng-tur`, `eng-jpn` (only
   `jpn_Hani`/`jpn_Kana`); Spanish/German/Turkish benign text comes from oasst instead.
5. in_the_wild carries 662 exact duplicates (4.4%) inside its own release; removed so eval metrics are not inflated.
6. NotInject never enters train; no train row collided with it.
