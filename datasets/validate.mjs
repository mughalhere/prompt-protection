#!/usr/bin/env node
// Validates the published datasets/ corpus. Node >= 20, no dependencies.
// Usage: node datasets/validate.mjs   (exit 0 = valid, 1 = invalid)
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const errors = [];
const seenIds = new Set();

function fail(file, line, msg) {
  errors.push(`${file}:${line}: ${msg}`);
}

function readLines(path) {
  return readFileSync(path, 'utf8').split('\n').filter((l) => l.trim().length > 0);
}

function parseSet(file, validate) {
  const path = join(HERE, file);
  const lines = readLines(path);
  const rows = [];
  lines.forEach((raw, i) => {
    const ln = i + 1;
    let obj;
    try {
      obj = JSON.parse(raw);
    } catch (e) {
      fail(file, ln, `invalid JSON: ${e.message}`);
      return;
    }
    if (!obj.id) return fail(file, ln, 'missing id');
    if (seenIds.has(obj.id)) fail(file, ln, `duplicate id ${obj.id}`);
    seenIds.add(obj.id);
    validate(obj, file, ln);
    rows.push(obj);
  });
  return rows;
}

function tally(rows, key) {
  const m = {};
  for (const r of rows) m[r[key]] = (m[r[key]] || 0) + 1;
  return m;
}

// ---- agent-flows.jsonl ----
const SCENARIOS = ['email-exfil','calendar-forward','file-exec','web-payment','rag-poison','mcp-tool','slack-relay','code-review','memory-persist','subagent-hop','split-identifier','approval-swap','tool-drift','loop-budget','depth-budget'];
const FLOW_LABELS = ['attack','benign'];
const ACTIONS = ['block','flag','allow'];
// Legacy prose reasons (rows af-001..100) plus the DecisionReason codes (src/guard/reasons.ts) used by `steps` rows.
const LEGACY_REASONS = ['tainted-identifier-to-sink','tainted-content-to-sink','injection-source-then-sink','none'];
const DECISION_REASONS = ['tool-unpinned','tool-drift','budget-exceeded','plan-violation','injection-source-flow','untrusted-to-exfil-sink','untrusted-to-exec','untrusted-to-payment','payment-confirm','injection-then-sink','args-injection','approval-mismatch','approval-expired','approved','lineage-untrusted','internal-error'];
const REASONS = [...LEGACY_REASONS, ...DECISION_REASONS];
const STEP_OPS = ['pin','lock','redefineTool','recordCost','trust','taint','memoryWrite','memoryRead','newGuard','fork','nextTurn','approve','advanceClock','call'];
const SINK_KINDS = ['network','email','message','file-write','exec','payment','none'];
const flows = parseSet('agent-flows.jsonl', (o, f, ln) => {
  if (!FLOW_LABELS.includes(o.label)) fail(f, ln, `bad label ${o.label}`);
  if (!SCENARIOS.includes(o.scenario)) fail(f, ln, `bad scenario ${o.scenario}`);
  if (typeof o.user !== 'string' || !o.user) fail(f, ln, 'missing user');
  if (!Array.isArray(o.sources)) fail(f, ln, 'sources not array');
  for (const s of o.sources || []) {
    if (!s.id || !s.tool || typeof s.text !== 'string') fail(f, ln, 'malformed source');
  }
  if (!o.call || !o.call.toolName || typeof o.call.args !== 'object') fail(f, ln, 'malformed call');
  if (!o.sinks || typeof o.sinks !== 'object') fail(f, ln, 'missing sinks map');
  for (const [t, k] of Object.entries(o.sinks || {})) {
    if (!SINK_KINDS.includes(k)) fail(f, ln, `bad sink kind ${k} for ${t}`);
  }
  if (o.call && o.sinks && !(o.call.toolName in o.sinks)) fail(f, ln, `call tool ${o.call.toolName} absent from sinks map`);
  if (!ACTIONS.includes(o.expect)) fail(f, ln, `bad expect ${o.expect}`);
  if (!REASONS.includes(o.expect_reason)) fail(f, ln, `bad expect_reason ${o.expect_reason}`);
  if (typeof o.notes !== 'string' || !o.notes) fail(f, ln, 'missing notes');
  if (o.steps !== undefined) {
    if (!Array.isArray(o.steps)) fail(f, ln, 'steps not array');
    for (const st of o.steps || []) if (!st || !STEP_OPS.includes(st.op)) fail(f, ln, `bad step op ${st && st.op}`);
    if (!DECISION_REASONS.includes(o.expect_reason) && o.expect_reason !== 'none') fail(f, ln, `steps row must use a DecisionReason or none, got ${o.expect_reason}`);
  }
  if (o.options !== undefined && (typeof o.options !== 'object' || o.options === null)) fail(f, ln, 'options not object');
});

// ---- benign-hard.jsonl ----
const BH_CATS = ['common-query','technique-query','virtual-creation','multilingual','dev-jargon','security-docs'];
const benignHard = parseSet('benign-hard.jsonl', (o, f, ln) => {
  if (o.label !== 0) fail(f, ln, `bad label ${o.label} (expected 0)`);
  if (!BH_CATS.includes(o.category)) fail(f, ln, `bad category ${o.category}`);
  if (typeof o.text !== 'string' || !o.text) fail(f, ln, 'missing text');
  if (!Array.isArray(o.triggers) || o.triggers.length === 0) fail(f, ln, 'missing triggers');
});

// ---- attacks.jsonl ----
const AT_CATS = ['prompt-injection','jailbreak','data-exfiltration','system-prompt-leak','role-manipulation','encoding-obfuscation','tool-poisoning','indirect-injection','multilingual'];
const attacks = parseSet('attacks.jsonl', (o, f, ln) => {
  if (o.label !== 1) fail(f, ln, `bad label ${o.label} (expected 1)`);
  if (!AT_CATS.includes(o.category)) fail(f, ln, `bad category ${o.category}`);
  if (typeof o.technique !== 'string' || !o.technique) fail(f, ln, 'missing technique');
  if (typeof o.text !== 'string' || !o.text) fail(f, ln, 'missing text');
});

// ---- disjointness from test fixtures ----
function norm(s) { return s.trim().toLowerCase().replace(/\s+/g, ' '); }
function loadFixture(p) {
  const full = join(ROOT, p);
  if (!existsSync(full)) return new Set();
  return new Set(readLines(full).map(norm));
}
const held = new Set([
  ...loadFixture('tests/__fixtures__/malicious.txt'),
  ...loadFixture('tests/__fixtures__/benign.txt'),
  ...loadFixture('bench/corpus/attacks.txt'),
  ...loadFixture('bench/corpus/benign.txt'),
]);
let overlaps = 0;
for (const [file, rows] of [['attacks.jsonl', attacks], ['benign-hard.jsonl', benignHard]]) {
  for (const r of rows) {
    if (held.has(norm(r.text))) { overlaps++; fail(file, r.id, `text overlaps a test/bench fixture`); }
  }
}

// ---- summary ----
const flowAttack = flows.filter((r) => r.label === 'attack').length;
const flowBenign = flows.filter((r) => r.label === 'benign').length;
console.log('=== datasets validation ===');
console.log(`agent-flows.jsonl : ${flows.length} (attack ${flowAttack}, benign ${flowBenign})`);
console.log('  scenario:', JSON.stringify(tally(flows, 'scenario')));
console.log('  expect  :', JSON.stringify(tally(flows, 'expect')));
console.log('  reason  :', JSON.stringify(tally(flows, 'expect_reason')));
console.log(`benign-hard.jsonl : ${benignHard.length}`);
console.log('  category:', JSON.stringify(tally(benignHard, 'category')));
console.log(`attacks.jsonl     : ${attacks.length}`);
console.log('  category:', JSON.stringify(tally(attacks, 'category')));
const langsHit = new Set(attacks.filter((a) => a.category === 'multilingual').map((a) => a.technique.split('-')[0]));
console.log('  multilingual techniques (lang prefixes):', langsHit.size, [...langsHit].join(','));
console.log(`fixture overlaps  : ${overlaps}`);
console.log(`total ids         : ${seenIds.size}`);

if (errors.length) {
  console.error(`\nFAILED with ${errors.length} error(s):`);
  for (const e of errors.slice(0, 50)) console.error('  ' + e);
  process.exit(1);
}
console.log('\nOK, all rows valid, ids unique, disjoint from fixtures.');
