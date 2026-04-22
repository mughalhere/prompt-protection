import { score } from '../src/scorer';
import type { PatternRule } from '../src/types';

const makeRule = (id: string, pattern: RegExp, weight: number): PatternRule => ({
  id,
  category: 'prompt-injection',
  pattern,
  weight,
  description: `Test rule ${id}`,
});

describe('scorer', () => {
  it('returns score 0 for text with no matches', () => {
    const rules = [makeRule('r1', /inject/i, 10)];
    const result = score(rules, 'hello world', 'hello world');
    expect(result.normalizedScore).toBe(0);
    expect(result.matches).toHaveLength(0);
  });

  it('single weight-10 rule scores above 0 but threshold math works', () => {
    const rules = [makeRule('r1', /ignore previous instructions/i, 10)];
    const text = 'ignore previous instructions';
    const result = score(rules, text, text);
    expect(result.rawScore).toBe(10);
    // 100 * (1 - e^(-10/15)) ≈ 49
    expect(result.normalizedScore).toBeGreaterThan(40);
    expect(result.normalizedScore).toBeLessThan(55);
  });

  it('two rules together push score higher', () => {
    const rules = [
      makeRule('r1', /ignore previous/i, 8),
      makeRule('r2', /dan mode/i, 8),
    ];
    const text = 'ignore previous instructions dan mode enabled';
    const result = score(rules, text, text);
    expect(result.rawScore).toBe(16);
    expect(result.normalizedScore).toBeGreaterThan(55);
  });

  it('diminishing returns: repeated same rule ID adds only 25% per extra hit', () => {
    const rules = [makeRule('r1', /foo/ig, 10)];
    const text = 'foo foo foo foo';
    const result = score(rules, text, text);
    // First hit: 10, 2nd: 2.5, 3rd: 2.5, 4th: 2.5 → raw = 17.5
    expect(result.rawScore).toBeCloseTo(17.5, 0);
  });

  it('different rule IDs do not share diminishing returns', () => {
    const rules = [
      makeRule('r1', /foo/i, 10),
      makeRule('r2', /bar/i, 10),
    ];
    const text = 'foo bar';
    const result = score(rules, text, text);
    expect(result.rawScore).toBe(20);
  });

  it('captures match text and positions', () => {
    const rules = [makeRule('r1', /secret/i, 5)];
    const text = 'this is a secret message';
    const result = score(rules, text, text);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]?.matchedText).toBe('secret');
    expect(result.matches[0]?.startIndex).toBe(10);
  });

  it('normalized score never exceeds 100', () => {
    const manyRules = Array.from({ length: 20 }, (_, i) =>
      makeRule(`r${i}`, new RegExp(`keyword${i}`, 'i'), 10),
    );
    const text = Array.from({ length: 20 }, (_, i) => `keyword${i}`).join(' ');
    const result = score(manyRules, text, text);
    expect(result.normalizedScore).toBeLessThanOrEqual(100);
  });
});
