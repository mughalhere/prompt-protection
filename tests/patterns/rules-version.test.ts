import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ALL_RULES, OUTPUT_RULES, TOOL_RULES } from '../../src/patterns/index';
import { RULES_VERSION } from '../../src/patterns/version';
import { fnv1a64Hex } from '../../src/utils/digest';

/** Deterministic digest of every shipped rule's identity, pattern, weight and precision. */
export function rulesDigest(): string {
  const lines = [...ALL_RULES, ...OUTPUT_RULES, ...TOOL_RULES]
    .map((r) => `${r.id}|${r.pattern.source}|${r.pattern.flags}|${r.weight}|${r.precision ?? 'medium'}`)
    .sort();
  return fnv1a64Hex(lines.join('\n'));
}

describe('rule-pack pinning', () => {
  it('RULES_VERSION is a date stamp', () => {
    expect(RULES_VERSION).toMatch(/^\d{4}\.\d{2}\.\d{2}$/);
  });

  it('any rule change must bump RULES_VERSION and the committed digest together', () => {
    const fixture = JSON.parse(readFileSync(join(__dirname, '..', '__fixtures__', 'rules-digest.json'), 'utf8')) as {
      rulesVersion: string;
      digest: string;
    };
    const digest = rulesDigest();
    if (digest !== fixture.digest || RULES_VERSION !== fixture.rulesVersion) {
      throw new Error(
        `rule pack changed. Set RULES_VERSION in src/patterns/version.ts to today and write ` +
          `{"rulesVersion":"<that>","digest":"${digest}"} to tests/__fixtures__/rules-digest.json, then note it under "### Rules" in CHANGELOG.md.`,
      );
    }
    expect(digest).toBe(fixture.digest);
  });
});
