# prompt-protection datasets

A held-out, human-authored corpus for evaluating prompt-injection / agent-security
guards. Every item is **original** to this project and **disjoint** from the unit-test
fixtures (`tests/__fixtures__/*.txt`) and bench corpus (`bench/corpus/*`), so it measures
generalisation rather than memorisation. JSONL, one object per line, UTF-8.

## Files

### `agent-flows.jsonl`, tool-call guard scenarios (100: 50 attack / 50 benign)
Each row is a full agent turn: the user's instruction, the tool results (`sources`, which
may carry an injection), the tool `call` the model wants to make, an explicit `sinks` map
(tool → `network|email|message|file-write|exec|payment|none`), and the expected guard
decision. Fields: `id, label, scenario, user, sources[], call{toolName,args}, sinks,
expect (block|flag|allow), expect_reason, notes`.

### `benign-hard.jsonl`, over-defense discipline (155, all `label:0`)
Legitimate prompts that *contain* injection trigger vocabulary ("ignore", "override",
"jailbreak", "system prompt"). Categories: `common-query, technique-query,
virtual-creation, multilingual, dev-jargon, security-docs`. A guard that blocks these is
over-defending. Fields: `id, label, category, text, triggers[]`.

### `attacks.jsonl`, regex-evading attacks (130, all `label:1`)
Attacks a keyword scanner tends to miss: paraphrased overrides with no canonical phrase,
persona jailbreaks with no trigger words, encoding/obfuscation (base64, homoglyph,
zero-width, ROT13, hex, spaced), indirect injections embedded in realistic
emails/web/README/CSV, markdown-image/link exfil, role-tag forgery, MCP tool poisoning,
and 15 multilingual items across 14 languages. Fields: `id, label, category, technique, text`.

## How labels & expectations were assigned
- `attacks` / `benign-hard` labels are definitional (malicious intent = 1, legitimate = 0).
- `agent-flows.expect` follows the guard's documented policy order (block > confirm > flag):
  a tainted identifier or ≥12-char verbatim payload reaching an exfil/exec sink → `block`;
  an injection-scoring source with a same-turn sink but no shared identifier → `flag`
  (`injection-source-then-sink`); any **payment** sink, and cases where the recipient/URL
  comes from a tool result rather than being named by the user, → `flag` with confirm
  semantics (documented in `notes`); user-named recipients/URLs and read-only sinks → `allow`.
  The ~5 benign-labelled rows that expect `flag` are intentional confirm cases, each noted.

## Disjointness
`validate.mjs` normalises every `text` and asserts zero overlap with the four fixture files.
Run `node datasets/validate.mjs` (Node ≥20, no deps) to re-check schema, unique ids, enum
values, per-category counts, and disjointness.

## Licence & citation
Licensed **CC-BY-4.0** (see `LICENSE`). If you use this corpus, please cite:

> prompt-protection agent-security datasets (2026), https://github.com/mughalhere/prompt-protection, CC-BY-4.0.

## Contributing
Add rows that keep each file's schema and stay disjoint from the fixtures; prefer techniques
a pure-regex scanner would miss for `attacks`, and realistic legitimate uses of trigger
vocabulary for `benign-hard`. Run the validator before opening a PR, it must print `OK`.

## Hugging Face

Mirrored at [https://huggingface.co/datasets/promptprotection/agent-security-datasets](https://huggingface.co/datasets/promptprotection/agent-security-datasets). `training/publish_hf.py --upload` republishes from this folder; the dataset card is generated from `bench/results.json`.
