import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ALL_RULES, OUTPUT_RULES, TOOL_RULES } from '../../src/patterns/index';
import { RULE_MAPPINGS, withMappings } from '../../src/patterns/mappings';

const floor = JSON.parse(readFileSync(join(__dirname, '..', '__fixtures__', 'mappings-floor.json'), 'utf8')) as { inputCoverage: number };
const ID_SHAPES = [/^LLM(0[1-9]|10):2025$/, /^AML\.T\d{4}(\.\d{3})?$/, /^ASI(0[1-9]|10):2026$/, /^ATR-\d{4}-\d{5}$/];

describe('framework mappings', () => {
  it('every mapped id names an existing rule', () => {
    const known = new Set([...ALL_RULES, ...OUTPUT_RULES, ...TOOL_RULES].map((r) => r.id));
    for (const id of Object.keys(RULE_MAPPINGS)) expect(known.has(id)).toBe(true);
  });

  it('every framework id has a recognised shape (no invented ids)', () => {
    for (const m of Object.values(RULE_MAPPINGS)) {
      for (const id of [...(m.owaspLlm ?? []), ...(m.atlas ?? []), ...(m.owaspAsi ?? []), ...(m.atr ?? [])]) {
        expect(ID_SHAPES.some((re) => re.test(id))).toBe(true);
      }
    }
  });

  it('input-rule coverage does not fall below the committed floor', () => {
    const covered = ALL_RULES.filter((r) => RULE_MAPPINGS[r.id] !== undefined).length;
    const ratio = covered / ALL_RULES.length;
    // eslint-disable-next-line no-console
    console.log(`mappings: ${covered}/${ALL_RULES.length} input rules mapped (${(ratio * 100).toFixed(1)}%), floor ${floor.inputCoverage}`);
    expect(ratio).toBeGreaterThanOrEqual(floor.inputCoverage);
  });

  it('withMappings attaches without mutating and leaves unknown ids untouched', () => {
    const out = withMappings(ALL_RULES);
    expect(out.find((r) => r.id === 'injection-ignore-previous')?.mappings?.owaspLlm).toEqual(['LLM01:2025']);
    expect(ALL_RULES.find((r) => r.id === 'injection-ignore-previous')?.mappings).toBeUndefined();
    const unmapped = out.filter((r) => r.mappings === undefined);
    expect(unmapped.length).toBe(ALL_RULES.length - Object.keys(RULE_MAPPINGS).filter((id) => ALL_RULES.some((r) => r.id === id)).length);
  });
});
