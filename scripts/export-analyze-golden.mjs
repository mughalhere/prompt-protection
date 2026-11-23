// Writes tests/__fixtures__/analyze.golden.json and unicode-node.json from the built dist (plan design item 4).
// `--check` exits 1 when either committed file differs from a fresh export, or is missing.
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzePrompt } from '../dist/index.js';
import { ALL_RULES } from '../dist/internal.js';
import pyExport from './lib/py-export.cjs';

const major = Number(process.versions.node.split('.')[0]);
if (major !== 22) {
  console.error(`export-analyze-golden refuses to run on Node ${process.versions.node}; use Node 22.x (D11).`);
  process.exit(1);
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = join(ROOT, 'tests/__fixtures__');
const GOLDEN = join(FIXTURES, 'analyze.golden.json');
const UNICODE = join(FIXTURES, 'unicode-node.json');

const CORPUS_KEYS = new Set(['text', 'user', 'args']);

// Every string at any depth under a text, user or args key, depth-first in key order (e-6406d1).
function collectTexts(value, inScope, out) {
  if (typeof value === 'string') {
    if (inScope) out.push(value);
  } else if (Array.isArray(value)) {
    value.forEach((v) => collectTexts(v, inScope, out));
  } else if (value !== null && typeof value === 'object') {
    for (const [key, v] of Object.entries(value)) collectTexts(v, inScope || CORPUS_KEYS.has(key), out);
  }
}

const nonEmptyLines = (text) => text.split('\n').filter((line) => line !== '');

function datasetTexts() {
  const texts = [];
  const files = readdirSync(join(ROOT, 'datasets')).filter((f) => f.endsWith('.jsonl')).sort();
  for (const file of files) {
    for (const line of nonEmptyLines(readFileSync(join(ROOT, 'datasets', file), 'utf8'))) {
      collectTexts(JSON.parse(line), false, texts);
    }
  }
  return texts.filter((t) => t !== '');
}

function buildCorpus() {
  const dataset = datasetTexts();
  const benign = nonEmptyLines(readFileSync(join(FIXTURES, 'benign.txt'), 'utf8'));
  const malicious = nonEmptyLines(readFileSync(join(FIXTURES, 'malicious.txt'), 'utf8'));
  const originOf = new Map();
  for (const [origin, texts] of [['dataset', dataset], ['fixture-benign', benign], ['fixture-malicious', malicious]]) {
    for (const t of texts) if (!originOf.has(t)) originOf.set(t, origin);
  }
  const corpus = pyExport.corpusTexts(dataset, [...benign, ...malicious]).map((text) => ({ text, origin: originOf.get(text) }));
  const vectors = pyExport.separatorVectors().map((text) => ({ text, origin: 'separator' }));
  const all = [...corpus, ...vectors];
  const seen = new Set();
  for (const { text } of all) {
    if (seen.has(text)) throw new Error(`a separator vector duplicates a corpus text: ${JSON.stringify(text)}`);
    seen.add(text);
  }
  return all;
}

function ruleMatches(text) {
  return ALL_RULES.flatMap((rule) => pyExport.ruleSpans(rule.pattern.source, text).map(([s, e]) => [rule.id, s, e]));
}

function buildCase({ text, origin }) {
  const result = analyzePrompt(text);
  return {
    text,
    origin,
    normalized: result.normalizedPrompt,
    score: result.score,
    severity: result.severity,
    action: result.action,
    categories: result.categories,
    ruleIds: result.matches.map((m) => m.rule.id),
    ruleMatches: { raw: ruleMatches(text), normalized: ruleMatches(result.normalizedPrompt) },
  };
}

const header = () => `  "unicode": ${JSON.stringify(process.versions.unicode)},\n  "icu": ${JSON.stringify(process.versions.icu)},\n`;

function goldenText() {
  const rows = buildCorpus().map((c) => `    ${JSON.stringify(buildCase(c))}`);
  return `{\n${header()}  "cases": [\n${rows.join(',\n')}\n  ]\n}\n`;
}

function mappingTable(map) {
  const rows = [];
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const ch = String.fromCodePoint(cp);
    const mapped = map(ch);
    if (mapped !== ch) rows.push(`    ${JSON.stringify(cp.toString(16).padStart(4, '0'))}: ${JSON.stringify(mapped)}`);
  }
  return `{\n${rows.join(',\n')}\n  }`;
}

function unicodeText() {
  const nfkc = mappingTable((ch) => ch.normalize('NFKC'));
  const lower = mappingTable((ch) => ch.toLowerCase());
  return `{\n${header()}  "nfkc": ${nfkc},\n  "lower": ${lower}\n}\n`;
}

const outputs = [[GOLDEN, goldenText()], [UNICODE, unicodeText()]];

if (process.argv.includes('--check')) {
  const stale = outputs.filter(([path, text]) => !existsSync(path) || readFileSync(path, 'utf8') !== text);
  if (stale.length > 0) {
    console.error('analyze golden is stale or missing. Run: node scripts/export-analyze-golden.mjs');
    process.exit(1);
  }
  console.log('analyze golden and unicode table are fresh');
} else {
  for (const [path, text] of outputs) writeFileSync(path, text);
  console.log(`wrote ${GOLDEN} and ${UNICODE}`);
}
