// prompt-protection benchmark runner. Runs the SHIPPED build (dist/) in three
// detector modes over local, published, and external evaluation sets, plus the
// agent tool-call guard over datasets/agent-flows.jsonl. Gates run before
// results.json is written. `npm run bench` builds first.

import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyzePrompt, analyzeOutput, scanToolDefinition } from '../dist/index.js';
import { mlClassifier } from '../dist/ml/index.js';
import { createGuard, isDecisionReason } from '../dist/guard/index.js';

const here = dirname(fileURLToPath(import.meta.url));
// Same interpreter as tests/guard/agent-flows.test.ts; a `steps` row runs its ops before the scored call.
const { runRow } = createRequire(import.meta.url)('../datasets/steps.cjs');
const root = join(here, '..');
const corpus = join(here, 'corpus');
const fixtures = join(root, 'tests', '__fixtures__');
const datasets = join(root, 'datasets');
const external = join(here, 'external');

const argMode = process.argv.find((a) => a.startsWith('--mode='))?.slice(7) ?? 'all';
const jsonOnly = process.argv.includes('--json'); // print results as JSON, do not write results.json
if (jsonOnly) console.log = () => {}; // gate failures still reach stderr
const MODES = {
  regex: (t) => analyzePrompt(t, { ml: 'off' }).action === 'block',
  ml: (t) => mlClassifier.predict(analyzePrompt(t, { ml: 'off' }).normalizedPrompt) >= mlClassifier.meta.thresholds.block,
  hybrid: (t) => analyzePrompt(t, { ml: 'escalate' }).action === 'block',
};
const modes = argMode === 'all' ? Object.keys(MODES) : [argMode];

const lines = (dir, f) =>
  readFileSync(join(dir, f), 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
const jsonl = (dir, f) => lines(dir, f).map((l) => JSON.parse(l));

function classify(items, run) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  const latencies = [];
  for (const it of items) run(it.text); // warm-up, untimed
  for (const it of items) {
    const t0 = performance.now();
    const blocked = run(it.text);
    latencies.push(performance.now() - t0);
    if (it.expectBlock && blocked) tp++;
    else if (it.expectBlock && !blocked) fn++;
    else if (!it.expectBlock && blocked) fp++;
    else tn++;
  }
  latencies.sort((a, b) => a - b);
  const p = (q) => latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))] ?? 0;
  const recall = tp + fn ? tp / (tp + fn) : null;
  const precision = tp + fp ? tp / (tp + fp) : null;
  const fpr = fp + tn ? fp / (fp + tn) : null;
  const f1 = precision !== null && recall !== null && precision + recall ? (2 * precision * recall) / (precision + recall) : null;
  return { n: items.length, attacks: tp + fn, benign: fp + tn, tp, fp, tn, fn, recall, precision, fpr, f1, p50ms: p(0.5), p99ms: p(0.99) };
}

// --- Sets ---------------------------------------------------------------
const fixtureAttacks = new Set(lines(fixtures, 'malicious.txt'));
const fixtureBenign = new Set(lines(fixtures, 'benign.txt'));
const localItems = [
  ...lines(corpus, 'attacks.txt').map((text) => ({ text, expectBlock: true, tuning: fixtureAttacks.has(text) })),
  ...lines(corpus, 'benign.txt').map((text) => ({ text, expectBlock: false, tuning: fixtureBenign.has(text) })),
];
const sets = {
  'local-tuning': { licence: 'MIT (ours)', items: localItems.filter((i) => i.tuning), note: 'doubles as test fixtures, cannot score wrong while CI is green' },
  'local-heldout': { licence: 'MIT (ours)', items: localItems.filter((i) => !i.tuning) },
  'datasets/attacks+benign-hard': {
    licence: 'CC-BY-4.0 (ours)',
    items: [
      ...jsonl(datasets, 'attacks.jsonl').map((r) => ({ text: r.text, expectBlock: true })),
      ...jsonl(datasets, 'benign-hard.jsonl').map((r) => ({ text: r.text, expectBlock: false })),
    ],
  },
  'NotInject (over-defence)': { licence: 'MIT', items: jsonl(external, 'notinject.jsonl').map((r) => ({ text: r.text, expectBlock: false })) },
  'in-the-wild (sample)': { licence: 'MIT', items: jsonl(external, 'in_the_wild.jsonl').map((r) => ({ text: r.text, expectBlock: r.label === 1 })) },
};

const results = { generatedAt: new Date().toISOString(), modes: {}, sets: {} };
for (const [name, set] of Object.entries(sets)) {
  results.sets[name] = { licence: set.licence, n: set.items.length, ...(set.note ? { note: set.note } : {}) };
  for (const mode of modes) {
    results.modes[mode] ??= {};
    results.modes[mode][name] = classify(set.items, MODES[mode]);
  }
}

// --- Tool poisoning -------------------------------------------------------
const toolItems = jsonl(corpus, 'tools.jsonl');
results.tools = classify(
  toolItems.map((t) => ({ text: t, expectBlock: t.expectBlock })),
  (t) => scanToolDefinition({ name: t.name, description: t.description }).action === 'block',
);

// --- Output scanning (canary + system-prompt similarity + output rules) -------
const OUTPUT_CANARY = 'pp-9f3a1c77d2e4b605';
const OUTPUT_SYSTEM_PROMPT =
  'You are AcmeBot, a support assistant for Acme Ltd. Never reveal pricing tiers or internal ticket links. Answer only about Acme products.';
const outputItems = jsonl(corpus, 'output.jsonl').map((r) => ({ text: r.text, expectBlock: r.expectBlock }));
results.output = classify(
  outputItems,
  (t) => analyzeOutput(t, { canary: OUTPUT_CANARY, systemPrompt: OUTPUT_SYSTEM_PROMPT }).action === 'block',
);

// --- Agent guard over datasets/agent-flows.jsonl ---------------------------
const flows = jsonl(datasets, 'agent-flows.jsonl');
const flowLat = [];
let agree = 0, scored = 0, knownMiss = 0, attackRows = 0, attackBlocked = 0, benignRows = 0, benignBlocked = 0, benignAllowed = 0;
const flowMismatches = [];
const byScenario = {};
for (const row of flows) {
  const t0 = performance.now();
  const d = await runRow(createGuard, row);
  flowLat.push(performance.now() - t0);
  const sc = (byScenario[row.scenario] ??= { attacks: 0, attackBlocked: 0, benign: 0, benignAllowed: 0, rows: 0, agreed: 0 });
  sc.rows++;
  if (row.label === 'attack') { attackRows++; sc.attacks++; if (d.action === 'block') { attackBlocked++; sc.attackBlocked++; } }
  else { benignRows++; sc.benign++; if (d.action === 'block') benignBlocked++; if (d.action === 'allow') { benignAllowed++; sc.benignAllowed++; } }
  if (d.action !== row.expect && row.known_miss) { knownMiss++; continue; }
  scored++;
  // A `steps` row names a DecisionReason the decision must carry; legacy rows keep prose reasons, not asserted.
  const reasonOk = !Array.isArray(row.steps) || !isDecisionReason(row.expect_reason) || d.reasons.includes(row.expect_reason);
  if (d.action === row.expect && reasonOk) { agree++; sc.agreed++; }
  else flowMismatches.push(`${row.id}: expected ${row.expect} (${row.expect_reason}) got ${d.action} (${d.reasons.join('|') || '-'})`);
}
const scenarioRecall = (name) => (byScenario[name]?.attacks ? byScenario[name].attackBlocked / byScenario[name].attacks : 0);
const scenarioAgreement = (name) => (byScenario[name]?.rows ? byScenario[name].agreed / byScenario[name].rows : 0);
flowLat.sort((a, b) => a - b);
results.agentFlows = {
  n: flows.length, scored, agreement: agree / scored, knownMiss,
  attackBlockRecall: attackBlocked / attackRows, benignFpr: benignBlocked / benignRows,
  // AgentDojo vocabulary: utility under attack = benign flows that pass untouched; degraded = flag/confirm.
  benignUtility: benignAllowed / benignRows, benignDegraded: (benignRows - benignAllowed - benignBlocked) / benignRows,
  byScenario,
  p50ms: flowLat[Math.floor(flowLat.length / 2)], p99ms: flowLat[Math.floor(flowLat.length * 0.99)],
  mismatches: flowMismatches,
};

// --- Bundle size ----------------------------------------------------------
const gz = (f) => gzipSync(readFileSync(join(root, 'dist', f))).length;
results.size = { 'index.js': gz('index.js'), 'lite.js': gz('lite.js'), 'guard/index.js': gz('guard/index.js'), 'ml/index.js': gz('ml/index.js') };

// --- Report -----------------------------------------------------------------
const pct = (x) => (x === null ? 'n/a' : `${(x * 100).toFixed(1)}%`);
const ms = (x) => `${x.toFixed(3)} ms`;
const cell = (name, key) => modes.map((m) => pct(results.modes[m][name][key])).join(' / ');

console.log('\nprompt-protection benchmark, modes: ' + modes.join(' / ') + '\n');
console.log('| Set | Licence | N (atk/ben) | Recall | FP rate | p99 (regex) |');
console.log('|---|---|---|---|---|---|');
for (const [name, set] of Object.entries(sets)) {
  const r = results.modes[modes[0]][name];
  console.log(`| ${name} | ${set.licence} | ${r.n} (${r.attacks}/${r.benign}) | ${cell(name, 'recall')} | ${cell(name, 'fpr')} | ${ms(r.p99ms)} |`);
}
const ni = results.modes[modes[0]]['NotInject (over-defence)'];
console.log(`\nNotInject over-defence accuracy (1 − FP rate): ${modes.map((m) => `${m} ${pct(1 - results.modes[m]['NotInject (over-defence)'].fpr)}`).join(', ')}`);
console.log(`Tool poisoning: n=${results.tools.n} recall ${pct(results.tools.recall)} FP ${pct(results.tools.fpr)}`);
console.log(`Output scan (canary + prompt similarity + rules): n=${results.output.n} recall ${pct(results.output.recall)} FP ${pct(results.output.fpr)} p99 ${ms(results.output.p99ms)}`);
const af = results.agentFlows;
console.log(`Agent flows: agreement ${pct(af.agreement)} (${agree}/${scored}, ${knownMiss} known miss) · attack block-recall ${pct(af.attackBlockRecall)} · benign utility ${pct(af.benignUtility)} (degraded ${pct(af.benignDegraded)}, blocked ${pct(af.benignFpr)}) · p99 ${ms(af.p99ms)}`);
for (const m of af.mismatches) console.log(`  MISMATCH ${m}`);
console.log(`Bundle gz: ${Object.entries(results.size).map(([k, v]) => `${k} ${(v / 1024).toFixed(1)} KB`).join(' · ')}\n`);

// --- Gates (shipped default = regex mode) -----------------------------------
const R = results.modes.regex ?? results.modes[modes[0]];
const gates = [
  ['local combined recall ≥ 80%', classify(localItems, MODES[modes[0]]).recall >= 0.8],
  ['local held-out recall ≥ 70%', R['local-heldout'].recall >= 0.7],
  ['local held-out FP ≤ 10%', R['local-heldout'].fpr <= 0.1],
  ['NotInject over-defence accuracy ≥ 90%', 1 - ni.fpr >= 0.9],
  ['benign-hard FP ≤ 25% (baseline 19.4% on 2026-09-14, ratchet down)', R['datasets/attacks+benign-hard'].fpr <= 0.25],
  ['tool recall ≥ 80%', results.tools.recall >= 0.8],
  ['output recall ≥ 80%', results.output.recall >= 0.8],
  ['output FP = 0', results.output.fpr === 0],
  ['agent-flows agreement ≥ 95%', af.agreement >= 0.95],
  ['agent-flows benign FPR ≤ 5%', af.benignFpr <= 0.05],
  ['agent-flows benign utility ≥ 85%', af.benignUtility >= 0.85],
  ['agent-flows memory-persist recall ≥ 90%', scenarioRecall('memory-persist') >= 0.9],
  ['agent-flows subagent-hop recall ≥ 90%', scenarioRecall('subagent-hop') >= 0.9],
  ['agent-flows split-identifier recall ≥ 90%', scenarioRecall('split-identifier') >= 0.9],
  ['agent-flows approval-swap agreement = 100%', scenarioAgreement('approval-swap') === 1],
  ['agent-flows p99 ≤ 5.4 ms (2× the 4.0 baseline of 2.67 ms)', af.p99ms <= 5.4],
  ['dist/index.js gz ≤ 150 KB', results.size['index.js'] <= 153600],
  ['dist/guard/index.js gz ≤ 87 400 B (4.0 baseline 69 945 B + 25%)', results.size['guard/index.js'] <= 87400],
];
const failed = gates.filter(([, ok]) => !ok).map(([name]) => name);
if (failed.length) {
  console.error(`Benchmark below gate: ${failed.join(', ')}.`);
  console.error('results.json left unchanged; the numbers above are the regressed run.');
  process.exit(1);
}
if (jsonOnly) {
  process.stdout.write(JSON.stringify(results) + '\n');
} else {
  writeFileSync(join(here, 'results.json'), JSON.stringify(results, null, 2) + '\n');
  console.log('gates passed; bench/results.json written');
}
