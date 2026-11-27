// Writes tests/guard/__fixtures__/envelope.golden.json from the built dist (D17, D29).
// `--check` validates the file and never compares bytes: every nonce is random, so no two exports match.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EnvelopeError, exportPublicKey, generateKey, importPublicKey, open, seal } from '../dist/envelope/index.js';
import { canonicalJson, createGuard } from '../dist/guard/index.js';
import pyExport from './lib/py-export.cjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const GOLDEN = join(ROOT, 'tests/guard/__fixtures__/envelope.golden.json');
const HEADER = Object.freeze({ secret: 'prompt-protection-envelope-golden-test-only-secret', now: 1_700_000_000_000 });

const pick = (inputs, ...fields) => Object.fromEntries(fields.filter((f) => inputs[f] !== undefined).map((f) => [f, inputs[f]]));
const hsKey = (header, inputs) => ({ alg: 'HS256', secret: header.secret, ...pick(inputs, 'kid') });
const sealOptions = (header, inputs) => ({ label: inputs.label, ...pick(inputs, 'ttlMs', 'from'), now: () => header.now });
const tainted = (inputs) => {
  const guard = createGuard();
  for (const t of inputs.taints) guard.taint(t.tool, t.text);
  return guard;
};

async function sealOne(header, vector) {
  const { kind, inputs } = vector;
  switch (kind) {
    case 'hs256':
      return seal(inputs.payload, hsKey(header, inputs), sealOptions(header, inputs));
    case 'handoff':
      return tainted(inputs).sealHandoff(hsKey(header, inputs), pick(inputs, 'ttlMs', 'from'));
    case 'memory': {
      const guard = createGuard();
      const { entry } = guard.taintMemoryWrite(inputs.tool, inputs.value);
      return guard.sealMemoryEntry(entry, hsKey(header, inputs));
    }
    case 'lock':
      return createGuard().pin(inputs.tools);
    case 'eddsa': {
      const key = await generateKey('EdDSA', inputs.kid);
      return { envelope: await seal(inputs.payload, key, sealOptions(header, inputs)), publicKey: await exportPublicKey(key) };
    }
    case 'eddsa-handoff': {
      const key = await generateKey('EdDSA', inputs.kid);
      return { envelope: await tainted(inputs).sealHandoff(key, pick(inputs, 'ttlMs', 'from')), publicKey: await exportPublicKey(key) };
    }
    case 'error':
      return sealError(header, inputs);
    default:
      throw new Error(`unknown vector kind ${kind}`);
  }
}

async function sealError(header, inputs) {
  const envelope = await seal(inputs.payload, hsKey(header, inputs), sealOptions(header, inputs));
  if (inputs.code === 'bad-signature') {
    const flipped = envelope.sig[0] === 'A' ? 'B' : 'A';
    return { envelope: { ...envelope, sig: `${flipped}${envelope.sig.slice(1)}` }, code: inputs.code, now: header.now };
  }
  return { envelope, code: inputs.code, now: envelope.exp + 1 };
}

async function buildGolden() {
  const vectors = [];
  for (const vector of pyExport.envelopeVectors()) vectors.push({ ...vector, output: await sealOne(HEADER, vector) });
  return { header: { ...HEADER }, vectors };
}

function goldenText(golden) {
  const rows = golden.vectors.map((v) => `    ${JSON.stringify(v)}`).join(',\n');
  return `{\n  "header": ${JSON.stringify(golden.header)},\n  "vectors": [\n${rows}\n  ]\n}\n`;
}

const codeOf = async (attempt) => {
  try {
    await attempt;
    return 'ok';
  } catch (error) {
    return error instanceof EnvelopeError ? error.code : `other:${String(error)}`;
  }
};
const openAt = (envelope, key, at) => open(envelope, key, { now: () => at });

async function validateOutput(header, vector) {
  const { kind, inputs, output } = vector;
  if (kind === 'hs256' || kind === 'handoff') {
    return (await codeOf(openAt(output, hsKey(header, inputs), output.iat))) === 'ok' ? [] : ['does not open under HS256 at its iat'];
  }
  if (kind === 'memory') {
    const envelope = JSON.parse(output.sig);
    return (await codeOf(openAt(envelope, hsKey(header, inputs), envelope.iat))) === 'ok' ? [] : ['sig does not open under HS256 at its iat'];
  }
  if (kind === 'eddsa' || kind === 'eddsa-handoff') {
    const key = await importPublicKey(output.publicKey, inputs.kid);
    return (await codeOf(openAt(output.envelope, key, output.envelope.iat))) === 'ok' ? [] : ['does not verify under the recorded public key'];
  }
  if (kind === 'error') {
    const got = await codeOf(openAt(output.envelope, hsKey(header, inputs), output.now));
    return got === output.code ? [] : [`opens with ${got}, recorded ${output.code}`];
  }
  return kind === 'lock' ? [] : [`unknown kind ${kind}`];
}

async function problemsOf(golden) {
  const { header, vectors } = golden;
  if (typeof header?.secret !== 'string' || header.secret === '' || !Number.isFinite(header.now) || !Array.isArray(vectors)) {
    return ['header or vectors missing'];
  }
  const expected = JSON.parse(JSON.stringify(pyExport.envelopeVectors()));
  const recorded = vectors.map(({ name, kind, inputs }) => ({ name, kind, inputs }));
  if (canonicalJson(recorded) !== canonicalJson(expected)) return ['recorded names, kinds and inputs differ from envelopeVectors()'];
  const problems = [];
  for (const vector of vectors) {
    try {
      problems.push(...(await validateOutput(header, vector)).map((p) => `${vector.name}: ${p}`));
    } catch (error) {
      problems.push(`${vector.name}: ${String(error)}`);
    }
  }
  return problems;
}

if (process.argv.includes('--check')) {
  let problems;
  try {
    problems = await problemsOf(JSON.parse(readFileSync(GOLDEN, 'utf8')));
  } catch (error) {
    problems = [`cannot read ${GOLDEN}: ${String(error)}`];
  }
  if (problems.length > 0) {
    console.error(`envelope golden is invalid:\n${problems.map((p) => `  ${p}`).join('\n')}\nRun: node scripts/export-envelope-golden.mjs`);
    process.exit(1);
  }
  console.log('envelope golden is valid');
} else {
  mkdirSync(dirname(GOLDEN), { recursive: true });
  writeFileSync(GOLDEN, goldenText(await buildGolden()));
  console.log(`wrote ${GOLDEN}`);
}
