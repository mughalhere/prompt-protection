import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checkSync } from 'recheck';
import { collectRegexes } from './collect';

interface AllowlistEntry {
  source: string;
  flags: string;
  status: 'unknown';
  error_kind?: string;
  reviewed_by: string;
  date: string;
  justification: string;
}

const allowlist = JSON.parse(readFileSync(join(__dirname, 'allowlist.json'), 'utf8')) as AllowlistEntry[];
const allowed = new Map(allowlist.map((e) => [`${e.flags}/${e.source}`, e]));
const regexes = collectRegexes();
const tally = { safe: 0, allowlisted: 0 };

describe(`ReDoS safety — ${regexes.length} regexes fuzzed with recheck`, () => {
  it.each(regexes.map((r) => [`${r.owner}/${r.id}`, r] as const))('%s', (_name, r) => {
    const result = checkSync(r.source, r.flags, { checker: 'auto', timeout: 5000 });
    if (result.status === 'safe') {
      tally.safe++;
      return;
    }
    if (result.status === 'vulnerable') {
      const attack = 'attack' in result ? JSON.stringify(result.attack).slice(0, 200) : '';
      throw new Error(`VULNERABLE ${r.owner}/${r.id} /${r.source}/${r.flags} — ${result.complexity?.summary ?? ''} ${attack}`);
    }
    const entry = allowed.get(`${r.flags}/${r.source}`);
    if (!entry) {
      const kind = 'error' in result ? JSON.stringify(result.error) : 'unknown';
      throw new Error(`UNKNOWN (not allowlisted) ${r.owner}/${r.id} /${r.source}/${r.flags} — ${kind}`);
    }
    tally.allowlisted++;
  });

  afterAll(() => {
    // eslint-disable-next-line no-console
    console.log(`recheck: ${tally.safe} safe, ${tally.allowlisted} reviewed-unknown (allowlisted), 0 vulnerable of ${regexes.length}`);
  });
});

describe('allowlist hygiene', () => {
  it('every allowlist entry still names a live regex and carries a justification', () => {
    const live = new Set(regexes.map((r) => `${r.flags}/${r.source}`));
    for (const e of allowlist) {
      expect(live.has(`${e.flags}/${e.source}`)).toBe(true);
      expect(e.justification.length).toBeGreaterThan(20);
      expect(e.reviewed_by.length).toBeGreaterThan(0);
    }
  });
});
