import { fuseVerdict, ML_RULE_ID } from '../../src/ml/fusion';
import { computeSeverity } from '../../src/core/analyze';
import type { AnalysisResult, PatternMatch, RulePrecision, ThreatCategory, MlMode, Action } from '../../src/types';
import type { ClassifierMeta } from '../../src/ml/types';

const META: ClassifierMeta = { version: 't', buckets: 16, thresholds: { flag: 0.6, block: 0.9, benign: 0.1 } };
const THRESHOLD = 35;

function match(category: ThreatCategory, precision: RulePrecision = 'medium'): PatternMatch {
  return {
    rule: { id: `${category}-${precision}`, category, pattern: /x/, weight: 5, precision, description: '' },
    matchedText: 'x',
    startIndex: 3,
    endIndex: 4,
  };
}

function base(action: Action, score: number, matches: PatternMatch[] = []): AnalysisResult {
  return {
    score,
    severity: computeSeverity(score),
    isMalicious: action === 'block',
    action,
    matches,
    categories: [...new Set(matches.map((m) => m.rule.category))],
    normalizedPrompt: 'normalized prompt text',
  };
}

const weakBlock = () => base('block', 40, [match('jailbreak')]);

describe('fuseVerdict', () => {
  it('returns the rules result untouched in off mode', () => {
    const r = base('allow', 0);
    expect(fuseVerdict(r, 0.99, 'off', META, THRESHOLD)).toBe(r);
    expect(r.ml).toBeUndefined();
  });

  const table: Array<{
    name: string;
    mode: MlMode;
    input: AnalysisResult;
    p: number;
    action: Action;
    contributed: 'none' | 'escalated' | 'flagged' | 'downgraded';
    score?: number;
  }> = [
    { name: 'allow → block at p ≥ block', mode: 'escalate', input: base('allow', 0), p: 0.95, action: 'block', contributed: 'escalated', score: 35 },
    { name: 'allow → block exactly at block', mode: 'escalate', input: base('allow', 10), p: 0.9, action: 'block', contributed: 'escalated', score: 35 },
    { name: 'flag → block at p ≥ block', mode: 'escalate', input: base('flag', 20, [match('jailbreak', 'low')]), p: 0.95, action: 'block', contributed: 'escalated', score: 35 },
    { name: 'block keeps its higher score', mode: 'escalate', input: base('block', 60, [match('jailbreak')]), p: 0.95, action: 'block', contributed: 'none', score: 60 },
    { name: 'allow → flag at p = flag', mode: 'escalate', input: base('allow', 5), p: 0.6, action: 'flag', contributed: 'flagged', score: 5 },
    { name: 'allow → flag just under block', mode: 'escalate', input: base('allow', 5), p: 0.8999, action: 'flag', contributed: 'flagged', score: 5 },
    { name: 'flag stays flag in the flag band', mode: 'escalate', input: base('flag', 20, [match('jailbreak', 'low')]), p: 0.7, action: 'flag', contributed: 'none' },
    { name: 'block stays block in the flag band', mode: 'escalate', input: base('block', 60, [match('jailbreak')]), p: 0.7, action: 'block', contributed: 'none' },
    { name: 'allow stays allow under flag', mode: 'escalate', input: base('allow', 0), p: 0.5999, action: 'allow', contributed: 'none' },
    { name: 'escalate never downgrades a weak block', mode: 'escalate', input: weakBlock(), p: 0.0, action: 'block', contributed: 'none' },
    { name: 'hybrid downgrades a weak block at p ≤ benign', mode: 'hybrid', input: weakBlock(), p: 0.05, action: 'flag', contributed: 'downgraded', score: 40 },
    { name: 'hybrid downgrades exactly at benign', mode: 'hybrid', input: weakBlock(), p: 0.1, action: 'flag', contributed: 'downgraded' },
    { name: 'hybrid keeps a weak block just above benign', mode: 'hybrid', input: weakBlock(), p: 0.1001, action: 'block', contributed: 'none' },
    { name: 'hybrid keeps a block with a high-precision match', mode: 'hybrid', input: base('block', 40, [match('jailbreak', 'high')]), p: 0.0, action: 'block', contributed: 'none' },
    { name: 'hybrid keeps a two-category block', mode: 'hybrid', input: base('block', 40, [match('jailbreak'), match('prompt-injection')]), p: 0.0, action: 'block', contributed: 'none' },
    { name: 'hybrid keeps a block at score ≥ threshold + 15', mode: 'hybrid', input: base('block', 50, [match('jailbreak')]), p: 0.0, action: 'block', contributed: 'none' },
    { name: 'hybrid still escalates allow → block', mode: 'hybrid', input: base('allow', 0), p: 0.95, action: 'block', contributed: 'escalated', score: 35 },
    { name: 'hybrid still flags allow in the flag band', mode: 'hybrid', input: base('allow', 0), p: 0.7, action: 'flag', contributed: 'flagged' },
  ];

  it.each(table)('$name', ({ mode, input, p, action, contributed, score }) => {
    const out = fuseVerdict(input, p, mode, META, THRESHOLD, 'original text');
    expect(out.action).toBe(action);
    expect(out.isMalicious).toBe(action === 'block');
    expect(out.ml).toEqual({ probability: p, contributed });
    if (score !== undefined) expect(out.score).toBe(score);
    expect(out.severity).toBe(computeSeverity(out.score));
    const synthetic = out.matches.filter((m) => m.rule.id === ML_RULE_ID);
    if (contributed === 'escalated' || contributed === 'flagged') {
      expect(synthetic).toHaveLength(1);
      expect(out.matches.length).toBe(input.matches.length + 1);
      expect(out.categories).toContain('prompt-injection');
    } else {
      expect(synthetic).toHaveLength(0);
      expect(out.matches).toBe(input.matches);
    }
  });

  it('escalation adds a weight-10 high-precision synthetic match over the original text', () => {
    const long = 'a'.repeat(200);
    const out = fuseVerdict(base('allow', 0), 0.99, 'escalate', META, THRESHOLD, long);
    const m = out.matches[0] as PatternMatch;
    expect(m.rule).toMatchObject({ id: ML_RULE_ID, category: 'prompt-injection', weight: 10, precision: 'high' });
    expect(m.rule.pattern.test('anything')).toBe(false);
    expect(m.matchedText).toBe('a'.repeat(80));
    expect([m.startIndex, m.endIndex]).toEqual([0, 0]);
    expect(out.severity).toBe('low');
  });

  it('flagging adds a weight-5 low-precision synthetic match, defaulting to the normalized prompt', () => {
    const out = fuseVerdict(base('allow', 0), 0.7, 'escalate', META, THRESHOLD);
    const m = out.matches[0] as PatternMatch;
    expect(m.rule).toMatchObject({ id: ML_RULE_ID, weight: 5, precision: 'low' });
    expect(m.matchedText).toBe('normalized prompt text');
  });

  it('downgrade keeps score, matches and categories', () => {
    const input = weakBlock();
    const out = fuseVerdict(input, 0.0, 'hybrid', META, THRESHOLD);
    expect(out.matches).toBe(input.matches);
    expect(out.categories).toEqual(input.categories);
    expect(out.score).toBe(input.score);
  });

  it('never breaks isMalicious === (action === block) and escalate never lowers the action', () => {
    const rank: Record<Action, number> = { allow: 0, flag: 1, block: 2 };
    let seed = 12345;
    const rnd = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 2 ** 32);
    const actions: Action[] = ['allow', 'flag', 'block'];
    const precisions: RulePrecision[] = ['low', 'medium', 'high'];
    for (let i = 0; i < 1000; i++) {
      const action = actions[Math.floor(rnd() * 3)] as Action;
      const matches = action === 'allow' ? [] : [match('jailbreak', precisions[Math.floor(rnd() * 3)] as RulePrecision)];
      const input = base(action, Math.floor(rnd() * 100), matches);
      const mode: MlMode = rnd() < 0.5 ? 'escalate' : 'hybrid';
      const out = fuseVerdict(input, rnd(), mode, META, THRESHOLD);
      expect(out.isMalicious).toBe(out.action === 'block');
      if (mode === 'escalate') expect(rank[out.action]).toBeGreaterThanOrEqual(rank[input.action]);
      expect(out.ml?.probability).toBeGreaterThanOrEqual(0);
    }
  });
});
