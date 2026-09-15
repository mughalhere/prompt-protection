import { analyzePrompt, verifyPrompt } from '../src/api';
import { analyzeOutput } from '../src/output';
import { verifyPromptAsync } from '../src/async';
import { PromptInjectionError } from '../src/error';
import type { ProtectionEvent } from '../src/types';

/** A regex whose `.source` getter throws — the scorer reads it when compiling allowlist patterns. */
function faultyPattern(): RegExp {
  return new Proxy(/x/, {
    get(target, prop, receiver) {
      if (prop === 'source' || prop === 'flags') throw new Error('boom: pattern');
      return Reflect.get(target, prop, receiver) as unknown;
    },
  });
}

describe('fail-closed: analyzePrompt', () => {
  it('blocks with an internal-error match when analysis throws (default)', () => {
    const events: ProtectionEvent[] = [];
    const result = analyzePrompt('hello there', {
      allowlistPatterns: [faultyPattern()],
      logger: { log: (e) => events.push(e) },
    });
    expect(result.action).toBe('block');
    expect(result.isMalicious).toBe(true);
    expect(result.matches.map((m) => m.rule.id)).toEqual(['internal-error']);
    expect(result.error).toEqual({ code: 'internal-error', message: 'boom: pattern' });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ type: 'input.blocked', error: 'boom: pattern' });
  });

  it("allows with error populated under failMode: 'open'", () => {
    const result = analyzePrompt('hello there', { allowlistPatterns: [faultyPattern()], failMode: 'open' });
    expect(result.action).toBe('allow');
    expect(result.isMalicious).toBe(false);
    expect(result.matches).toHaveLength(0);
    expect(result.error?.code).toBe('internal-error');
  });

  it('verifyPrompt throws a PromptInjectionError whose first rule is internal-error', () => {
    try {
      verifyPrompt('hello there', { allowlistPatterns: [faultyPattern()] });
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(PromptInjectionError);
      expect((err as PromptInjectionError).matches[0]?.rule.id).toBe('internal-error');
    }
  });

  it('a throwing logger never changes the verdict', () => {
    const result = analyzePrompt('what is the weather', {
      logger: {
        log: () => {
          throw new Error('logger down');
        },
      },
      logLevels: ['allowed', 'flagged', 'blocked'],
    });
    expect(result.action).toBe('allow');
    expect(result.error).toBeUndefined();
  });
});

describe('fail-closed: analyzeOutput', () => {
  it('blocks by default and allows when open', () => {
    const closed = analyzeOutput('fine answer', { allowlistPatterns: [faultyPattern()] });
    expect(closed.action).toBe('block');
    expect(closed.isSuspicious).toBe(true);
    expect(closed.error?.code).toBe('internal-error');
    const open = analyzeOutput('fine answer', { allowlistPatterns: [faultyPattern()], failMode: 'open' });
    expect(open.action).toBe('allow');
    expect(open.error?.code).toBe('internal-error');
  });
});

describe('fail-closed: verifyPromptAsync', () => {
  const adapter = {
    analyze: () => Promise.reject(new Error('classifier down')),
  };

  it('propagates adapter failure by default (nothing passes)', async () => {
    await expect(verifyPromptAsync('what is the weather', { adapter })).rejects.toThrow('classifier down');
  });

  it("falls back to the sync verdict under failMode: 'open' (and the deprecated fallbackToSync)", async () => {
    await expect(verifyPromptAsync('what is the weather', { adapter, failMode: 'open' })).resolves.toBeUndefined();
    await expect(verifyPromptAsync('what is the weather', { adapter, fallbackToSync: true })).resolves.toBeUndefined();
  });
});
