// Bundle-size gate: gzip every ESM entry in dist/ and fail if the core entry
// exceeds its budget. Run after `tsup` via `npm run size`.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const CORE = 'index.js';
const FAIL_BYTES = 153_600;
const WARN_BYTES = 122_880;

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '..', '..', 'dist');

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (name.endsWith('.js')) out.push(p);
  }
  return out;
}

const rows = walk(dist)
  .map((p) => {
    const buf = readFileSync(p);
    return { entry: relative(dist, p), raw: buf.length, gz: gzipSync(buf).length };
  })
  .sort((a, b) => a.entry.localeCompare(b.entry));

const kb = (n) => (n / 1024).toFixed(1).padStart(7);
console.log(`${'entry'.padEnd(36)}${'raw KB'.padStart(8)}${'gz KB'.padStart(8)}`);
for (const r of rows) console.log(`${r.entry.padEnd(36)}${kb(r.raw)} ${kb(r.gz)}`);

const core = rows.find((r) => r.entry === CORE);
if (!core) {
  console.error(`size: dist/${CORE} not found, run the build first`);
  process.exit(1);
}
if (core.gz > FAIL_BYTES) {
  console.error(`size: dist/${CORE} is ${core.gz} B gz, over the ${FAIL_BYTES} B ceiling`);
  process.exit(1);
}
if (core.gz > WARN_BYTES) {
  console.warn(`size: warning, dist/${CORE} is ${core.gz} B gz, over the ${WARN_BYTES} B target`);
}
console.log(`size: dist/${CORE} ${core.gz} B gz (ceiling ${FAIL_BYTES})`);
