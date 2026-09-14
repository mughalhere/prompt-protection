#!/usr/bin/env node
// Applies the real runtime normalize() (dist/lite.js) so Python trains on what JS sees.
//   node normalize.mjs <in.jsonl> <out.jsonl>          adds `text_normalized` to every row
//   node normalize.mjs --strings <in.json> <out.json>  JSON array of strings → array of normalized strings
import { createReadStream, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import { normalize } from '../dist/lite.js';

const args = process.argv.slice(2);
if (args[0] === '--strings') {
  const input = JSON.parse(readFileSync(args[1], 'utf8'));
  writeFileSync(args[2], JSON.stringify(input.map((s) => normalize(s).normalized)));
  process.exit(0);
}
const [inPath, outPath] = args;
if (!inPath || !outPath) {
  console.error('usage: normalize.mjs <in.jsonl> <out.jsonl> | --strings <in.json> <out.json>');
  process.exit(2);
}
mkdirSync(dirname(outPath), { recursive: true });
const out = [];
const rl = createInterface({ input: createReadStream(inPath, 'utf8'), crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  const row = JSON.parse(line);
  row.text_normalized = normalize(row.text).normalized;
  out.push(JSON.stringify(row));
}
writeFileSync(outPath, out.join('\n') + (out.length ? '\n' : ''));
console.error(`${inPath} -> ${outPath}: ${out.length} rows`);
