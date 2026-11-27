// Writes tests/guard/__fixtures__/agent-flows.golden.json from the built dist (plan design item 4).
// `--check` exits 1 when the committed file differs from a fresh export, or is missing.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RULES_VERSION } from '../dist/index.js';
import { createGuard } from '../dist/guard/index.js';
import pyExport from './lib/py-export.cjs';
import steps from '../datasets/steps.cjs';

const major = Number(process.versions.node.split('.')[0]);
if (major !== 22) {
  console.error(`export-guard-golden refuses to run on Node ${process.versions.node}; use Node 22.x (D11).`);
  process.exit(1);
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const GOLDEN = join(ROOT, 'tests/guard/__fixtures__/agent-flows.golden.json');

const datasetRows = () => readFileSync(join(ROOT, 'datasets/agent-flows.jsonl'), 'utf8')
  .split('\n')
  .filter((line) => line !== '')
  .map((line) => JSON.parse(line));

async function buildRow(row) {
  const rec = pyExport.recordingFactory(createGuard);
  const decision = await steps.runRow(rec.factory, row);
  return { id: row.id, decision: pyExport.projectDecision(decision), cards: rec.cards, locks: rec.locks };
}

async function goldenText() {
  const rows = [];
  for (const row of datasetRows()) rows.push(`    ${JSON.stringify(await buildRow(row))}`);
  const head = `  "node": "22",\n  "unicode": ${JSON.stringify(process.versions.unicode)},\n  "rulesVersion": ${JSON.stringify(RULES_VERSION)},\n`;
  return `{\n${head}  "rows": [\n${rows.join(',\n')}\n  ]\n}\n`;
}

const text = await goldenText();

if (process.argv.includes('--check')) {
  if (!existsSync(GOLDEN) || readFileSync(GOLDEN, 'utf8') !== text) {
    console.error('agent-flows golden is stale or missing. Run: node scripts/export-guard-golden.mjs');
    process.exit(1);
  }
  console.log('agent-flows golden is fresh');
} else {
  mkdirSync(dirname(GOLDEN), { recursive: true });
  writeFileSync(GOLDEN, text);
  console.log(`wrote ${GOLDEN}`);
}
