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

describe('/guard runtime surface (stable tier: additive only)', () => {
  it('exports exactly the documented runtime symbols', async () => {
    const guard = await import('../src/guard/index');
    expect(Object.keys(guard).sort()).toEqual(
      [
        'ApprovalMismatchError', 'CanonicalJsonError', 'DECISION_REASONS', 'DEFAULT_APPROVAL_MAX', 'DEFAULT_APPROVAL_TTL_MS',
        'DEFAULT_POLICIES', 'DEFAULT_SINK_PATTERNS', 'DESTINATION_KEYS', 'DESTINATION_KINDS', 'EXEC_SINKS', 'EXFIL_SINKS',
        'HandoffError', 'MIN_CONTENT_CHARS', 'MIN_CONTENT_WORDS', 'MIN_DESTINATION_CHARS', 'MIN_EDGE', 'MIN_EXACT_CHARS',
        'MIN_URL_PATH_CHARS', 'STRONG_EDGE', 'SourceIndex', 'TRUST_LABEL_RANK', 'ToolCallBlockedError', 'approvalExpired',
        'approvalMismatch', 'argsInjection', 'assertTaintHandoff', 'canonicalJson', 'checkToolCall', 'collectLeaves',
        'containmentOf', 'createApprovalStore', 'createGuard', 'createSinkResolver', 'createToolApproval', 'defang',
        'defaultSink', 'deriveLabel', 'detectFlows', 'digest', 'digestSyncWeak', 'evaluatePolicies', 'identifierValues',
        'injectionSourceFlow', 'injectionThenSink', 'isDecisionReason', 'isMemoryEntry', 'isTaintHandoff', 'keyOf',
        'lineageUntrusted', 'maxLabel', 'paymentConfirm', 'planViolation', 'rankOf', 'renderApprovalCard', 'stringifyValue',
        'toApprovalOutcome', 'untrustedToExec', 'untrustedToExfilSink', 'untrustedToPayment', 'urlPathOf', 'wrapTools',
        // 4.2
        'DEFAULT_MAX_REPEAT_IDENTICAL', 'UNLOCKED', 'budgetExceeded', 'createBudget', 'identityText', 'isToolLock',
        'pinTools', 'toolDrift', 'toolIdentities', 'toolIdentity', 'toolUnpinned', 'verifyTools',
      ].sort(),
    );
  });
});

describe('/spotlight runtime surface (stable tier since 4.2: additive only)', () => {
  it('exports exactly the documented runtime symbols', async () => {
    const spotlight = await import('../src/spotlight/index');
    expect(Object.keys(spotlight).sort()).toEqual(
      ['SPOTLIGHT_INSTRUCTION', 'createBoundary', 'isSpotlightBoundary', 'spotlight', 'spotlightInstruction', 'unspotlight'].sort(),
    );
  });
});
