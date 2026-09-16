import * as root from '../src/index';
import * as internal from '../src/internal';
import * as lite from '../src/lite';
import type { ThreatCategory, ProtectionEvent } from '../src/index';
import type { SinkKind } from '../src/guard/types';

const runtimeKeys = (mod: object) => Object.keys(mod).sort();

// docs/API_STABILITY.md is the contract; this test is the enforcement.
describe('API tiers', () => {
  it('root runtime exports are exactly the stable tier', () => {
    expect(runtimeKeys(root)).toEqual(
      [
        'ClaudeAdapter',
        'OpenAIAdapter',
        'PromptInjectionError',
        'RULES_VERSION',
        'analyzeOutput',
        'analyzePrompt',
        'createConsoleLogger',
        'createProtectionSession',
        'scanToolDefinition',
        'stripPrompt',
        'verifyPrompt',
        'verifyPromptAsync',
      ].sort(),
    );
  });

  it('every internal export resolves', () => {
    const entries = Object.entries(internal as Record<string, unknown>);
    expect(entries.length).toBeGreaterThan(10);
    for (const [name, value] of entries) expect([name, value === undefined]).toEqual([name, false]);
  });

  it('engine plumbing is reachable only through the internal entry', () => {
    for (const name of ['normalize', 'resolveAction', 'precisionAllowsBlock', 'computeSeverity', 'ALL_RULES']) {
      expect(typeof (internal as Record<string, unknown>)[name]).not.toBe('undefined');
      expect((root as Record<string, unknown>)[name]).toBeUndefined();
      expect((lite as Record<string, unknown>)[name]).toBeUndefined();
    }
  });

  it('keeps the result unions open so additions are not breaking', () => {
    const category: ThreatCategory = 'a-category-from-a-future-minor';
    const sink: SinkKind = 'a-sink-from-a-future-minor';
    const type: ProtectionEvent['type'] = 'memory.tainted';
    expect([category, sink, type].every((v) => typeof v === 'string')).toBe(true);
  });
});
