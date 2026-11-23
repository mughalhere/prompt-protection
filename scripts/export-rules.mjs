// Writes python/src/prompt_protection/_data/rules.json from the built dist (plan design item 1).
// `--check` exits 1 when the committed file differs from a fresh export, or is missing.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { withMappings } from '../dist/atr/index.js';
import { RULES_VERSION } from '../dist/index.js';
import { ALL_RULES, DEFERRED_REFERENCE_RULE_IDS } from '../dist/internal.js';
import pyExport from './lib/py-export.cjs';

const target = join(dirname(fileURLToPath(import.meta.url)), '../python/src/prompt_protection/_data/rules.json');
const json = pyExport.buildRulesJson(withMappings(ALL_RULES), RULES_VERSION, DEFERRED_REFERENCE_RULE_IDS);
const text = `${JSON.stringify(json, null, 2)}\n`;

if (process.argv.includes('--check')) {
  if (!existsSync(target) || readFileSync(target, 'utf8') !== text) {
    console.error('rules.json is stale or missing. Run: node scripts/export-rules.mjs');
    process.exit(1);
  }
  console.log('rules.json is fresh');
} else {
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, text);
  console.log(`wrote ${json.rules.length} rules to ${target}`);
}
