# prompt-protection v3 — training pipeline. `make train` will run the full chain once train.py lands.
PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: venv fetch mine-benign dedupe normalize train fit eval export golden report clean

venv: .venv/bin/python
.venv/bin/python: requirements.txt
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	touch .venv/bin/python

fetch: venv
	$(PY) fetch.py $(FETCH_ARGS)

# Licence-clean benign rows (label 0) → data/raw/benign_<name>.jsonl; needs eval sets from `fetch`.
mine-benign: venv
	$(PY) mine_benign.py $(MINE_ARGS)

# Real JS normalizer (dist/lite.js) over data/raw/*.jsonl + the local datasets → data/norm/.
# Rebuild dist first if src/ changed: ../node_modules/.bin/tsup (from the repo root).
normalize:
	@mkdir -p data/norm
	@for f in data/raw/*.jsonl; do node normalize.mjs $$f data/norm/$$(basename $$f); done
	node normalize.mjs ../datasets/attacks.jsonl data/norm/local_attacks.jsonl
	node normalize.mjs ../datasets/benign-hard.jsonl data/norm/local_benign_hard.jsonl

# Merges data/raw/<name>.jsonl + benign_*.jsonl; run after `fetch` and `mine-benign`.
dedupe: venv
	$(PY) dedupe.py $(DEDUPE_ARGS)

# Full chain: fetch → mine-benign → normalize → dedupe → fit → eval → export → golden → report.
train: fetch mine-benign normalize dedupe fit eval export golden report

# CV grid + LODO + final fit + thresholds + int8 quantisation → data/model/{model.json,metrics.json}
fit: venv
	$(PY) train.py $(TRAIN_ARGS)

eval: venv
	$(PY) evaluate.py

export: venv
	$(PY) export.py

golden: venv
	$(PY) export_golden.py

report: venv
	$(PY) report.py

clean:
	rm -rf data/raw data/norm data/dedupe data/feat data/model
