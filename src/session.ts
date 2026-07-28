import { analyzePrompt, computeSeverity, stripPrompt } from './api.js';
import { PromptInjectionError } from './error.js';
import { resolvePromptInput } from './messages.js';
import { DEFERRED_REFERENCE_RULE_IDS } from './patterns/injection.js';
import type {
  AnalysisResult,
  AnalyzeOptions,
  PatternMatch,
  PatternRule,
  PromptInput,
  StripOptions,
  ThreatCategory,
  VerifyOptions,
} from './types.js';

const DEFAULT_THRESHOLD = 35;
const DEFAULT_MAX_BLOCKED_HISTORY = 5;
const MAX_STORED_PROMPT_LENGTH = 500;

const CORRELATION_RULE: PatternRule = {
  id: 'session-correlate-blocked',
  category: 'prompt-injection',
  pattern: /(?!)/, // never matches text; synthetic matches only
  weight: 10,
  precision: 'high',
  description:
    'Deferred reference to a prior turn correlated with a previously blocked prompt',
};

export interface ProtectionSessionOptions extends AnalyzeOptions {
  /** Max blocked turns retained. Default: 5 */
  maxBlockedHistory?: number;
  /** Escalate when deferred-ref + non-empty blocked history. Default: true */
  correlateBlocked?: boolean;
}

export interface ProtectionSession {
  analyze(prompt: PromptInput, options?: AnalyzeOptions): AnalysisResult;
  verify(prompt: PromptInput, options?: VerifyOptions): void;
  strip(prompt: PromptInput, options?: StripOptions): string;
  clear(): void;
  getBlockedHistory(): readonly string[];
}

function hasDeferredReference(matches: PatternMatch[]): boolean {
  return matches.some((m) => DEFERRED_REFERENCE_RULE_IDS.has(m.rule.id));
}

function truncateForHistory(text: string): string {
  if (text.length <= MAX_STORED_PROMPT_LENGTH) return text;
  return `${text.slice(0, MAX_STORED_PROMPT_LENGTH)}…`;
}

function pushBlocked(
  history: string[],
  text: string,
  maxBlockedHistory: number,
): void {
  const entry = truncateForHistory(text);
  history.push(entry);
  while (history.length > maxBlockedHistory) {
    history.shift();
  }
}

function escalateWithCorrelation(
  result: AnalysisResult,
  threshold: number,
): AnalysisResult {
  const deferred = result.matches.find((m) =>
    DEFERRED_REFERENCE_RULE_IDS.has(m.rule.id),
  );
  const synthetic: PatternMatch = {
    rule: CORRELATION_RULE,
    matchedText: deferred?.matchedText ?? '',
    startIndex: deferred?.startIndex ?? 0,
    endIndex: deferred?.endIndex ?? 0,
  };

  const score = Math.max(result.score, threshold);
  const matches = [...result.matches, synthetic];
  const categories = [
    ...new Set([...result.categories, 'prompt-injection' as ThreatCategory]),
  ];

  return {
    ...result,
    score,
    severity: computeSeverity(score),
    action: 'block',
    isMalicious: true,
    matches,
    categories,
  };
}

/**
 * Creates a stateful protection session that remembers recently blocked prompts
 * and escalates deferred-reference follow-ups (e.g. "process the last prompt").
 *
 * Correlation is opt-in via this factory — free `analyzePrompt` / `verifyPrompt`
 * calls remain stateless.
 */
export function createProtectionSession(
  sessionOptions: ProtectionSessionOptions = {},
): ProtectionSession {
  const {
    maxBlockedHistory = DEFAULT_MAX_BLOCKED_HISTORY,
    correlateBlocked = true,
    ...defaultAnalyzeOptions
  } = sessionOptions;

  const blockedHistory: string[] = [];

  function analyze(
    prompt: PromptInput,
    options: AnalyzeOptions = {},
  ): AnalysisResult {
    const merged: AnalyzeOptions = { ...defaultAnalyzeOptions, ...options };
    const threshold = merged.threshold ?? DEFAULT_THRESHOLD;
    let result = analyzePrompt(prompt, merged);

    if (
      correlateBlocked &&
      blockedHistory.length > 0 &&
      hasDeferredReference(result.matches) &&
      result.action !== 'block'
    ) {
      result = escalateWithCorrelation(result, threshold);
    }

    if (result.action === 'block') {
      const text = resolvePromptInput(prompt, merged.analyzeRoles);
      pushBlocked(blockedHistory, text, maxBlockedHistory);
    }

    return result;
  }

  function verify(prompt: PromptInput, options: VerifyOptions = {}): void {
    const result = analyze(prompt, options);
    if (result.action === 'block') {
      throw new PromptInjectionError({
        score: result.score,
        matches: result.matches,
        categories: result.categories,
      });
    }
  }

  function strip(prompt: PromptInput, options: StripOptions = {}): string {
    const merged: StripOptions = { ...defaultAnalyzeOptions, ...options };
    // Run session analyze first so blocked history / correlation stay in sync.
    // Strip still only removes spans from the *current* prompt text.
    analyze(prompt, merged);
    return stripPrompt(prompt, merged);
  }

  return {
    analyze,
    verify,
    strip,
    clear() {
      blockedHistory.length = 0;
    },
    getBlockedHistory() {
      return [...blockedHistory];
    },
  };
}
