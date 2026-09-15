import { normalize } from '../normalizer.js';
import { score } from '../scorer.js';
import { ALL_RULES } from '../patterns/index.js';
import { PromptInjectionError } from '../error.js';
import { resolvePromptInput } from '../messages.js';
import { resolveAction } from '../verdict.js';
import { emitInputLog } from '../logging.js';
import { fuseVerdict } from '../ml/fusion.js';
import type { Classifier } from '../ml/types.js';
import type {
  AnalysisResult,
  AnalyzeOptions,
  FailMode,
  PatternRule,
  PromptInput,
  SeverityLevel,
  StripOptions,
  ThreatCategory,
  VerifyOptions,
} from '../types.js';

export const DEFAULT_THRESHOLD = 35;
export const DEFAULT_MAX_INPUT_LENGTH = 100_000;

export type AnalyzeFn = (prompt: PromptInput, options?: AnalyzeOptions) => AnalysisResult;

/** Bounds regex work on adversarial input by truncating over-long text before scoring. */
export function capLength(text: string, maxInputLength: number | undefined): string {
  const cap = maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
  return text.length > cap ? text.slice(0, cap) : text;
}

export function computeSeverity(s: number): SeverityLevel {
  if (s >= 80) return 'critical';
  if (s >= 65) return 'high';
  if (s >= 50) return 'medium';
  if (s >= 25) return 'low';
  return 'safe';
}

function splitSentences(text: string): string[] {
  return text.split(/[.!?]+\s+/).map((s) => s.trim()).filter((s) => s.length > 3);
}

/** Applies disabled-category / disabled-id / custom-rule options to a base rule set. */
export function buildRuleSet(options: AnalyzeOptions, base: readonly PatternRule[] = ALL_RULES): PatternRule[] {
  let rules = [...base];

  if (options.disabledCategories && options.disabledCategories.length > 0) {
    const disabled = new Set(options.disabledCategories);
    rules = rules.filter((r) => !disabled.has(r.category));
  }

  if (options.disabledRuleIds && options.disabledRuleIds.length > 0) {
    const disabled = new Set(options.disabledRuleIds);
    rules = rules.filter((r) => !disabled.has(r.id));
  }

  if (options.customRules && options.customRules.length > 0) {
    rules = [...rules, ...options.customRules];
  }

  return rules;
}

/**
 * Builds an `analyzePrompt` bound to an optional embedded classifier.
 * With `null` the result is rules-only (the 2.x behaviour). Otherwise the
 * classifier scores the same normalized text the rules saw and `fuseVerdict`
 * merges it in (`options.ml`, default `'off'` until the model clears the external bench; `'escalate'` enables it).
 */
export function analyzePromptWith(classifier: Classifier | null): AnalyzeFn {
  return function analyzePrompt(prompt: PromptInput, options: AnalyzeOptions = {}): AnalysisResult {
    const threshold = options.threshold ?? DEFAULT_THRESHOLD;
    try {
    const rules = buildRuleSet(options);
    const text = capLength(resolvePromptInput(prompt, options.analyzeRoles), options.maxInputLength);

    const { normalized, indexMap } = normalize(text);
    const { normalizedScore, matches } = score(rules, normalized, text, {
      indexMap,
      ...(options.allowlistPatterns ? { allowlistPatterns: options.allowlistPatterns } : {}),
      ...(options.allowlistRuleIds ? { allowlistRuleIds: options.allowlistRuleIds } : {}),
    });

    const categories = [...new Set(matches.map((m) => m.rule.category))] as ThreatCategory[];
    const action = resolveAction(normalizedScore, matches, threshold, options.flagThreshold);

    let result: AnalysisResult = {
      score: normalizedScore,
      severity: computeSeverity(normalizedScore),
      isMalicious: action === 'block',
      action,
      matches,
      categories,
      normalizedPrompt: normalized,
    };

    const mlMode = options.ml ?? 'off';
    if (classifier !== null && mlMode !== 'off') {
      const probability = classifier.predict(normalized);
      result = fuseVerdict(result, probability, mlMode, classifier.meta, threshold, text);
    }

    if (options.sentenceAnalysis === true) {
      const sentences = splitSentences(text);
      result.sentenceScores = sentences.map((sentence) => {
        const { normalized: normSent, indexMap: sentMap } = normalize(sentence);
        const { normalizedScore: sentScore } = score(rules, normSent, sentence, {
          indexMap: sentMap,
          ...(options.allowlistPatterns ? { allowlistPatterns: options.allowlistPatterns } : {}),
          ...(options.allowlistRuleIds ? { allowlistRuleIds: options.allowlistRuleIds } : {}),
        });
        return { sentence, score: sentScore };
      });
    }

    emitInputLog(result, text, options);

    return result;
    } catch (err) {
      const result = failedAnalysis(err, options.failMode ?? 'closed', threshold);
      emitInputLog(result, typeof prompt === 'string' ? prompt : '', options);
      return result;
    }
  };
}

/** Synthetic rule carried by a fail-closed block; `pattern` never matches text. */
export const INTERNAL_ERROR_RULE: PatternRule = {
  id: 'internal-error',
  category: 'prompt-injection',
  pattern: /(?!)/,
  weight: 10,
  precision: 'high',
  description: 'Analysis failed internally; verdict decided by failMode',
};

/** Builds the verdict for an internal failure: block when closed, allow when open. */
export function failedAnalysis(err: unknown, failMode: FailMode, threshold: number): AnalysisResult {
  const message = err instanceof Error ? err.message : String(err);
  const error = { code: 'internal-error' as const, message };
  if (failMode === 'open') {
    return { score: 0, severity: 'safe', isMalicious: false, action: 'allow', matches: [], categories: [], normalizedPrompt: '', error };
  }
  return {
    score: threshold,
    severity: computeSeverity(threshold),
    isMalicious: true,
    action: 'block',
    matches: [{ rule: INTERNAL_ERROR_RULE, matchedText: '', startIndex: 0, endIndex: 0 }],
    categories: [],
    normalizedPrompt: '',
    error,
  };
}

/** Builds a `verifyPrompt` that throws on `block` using the given analyzer. */
export function verifyPromptWith(analyze: AnalyzeFn) {
  return function verifyPrompt(prompt: PromptInput, options: VerifyOptions = {}): void {
    const result = analyze(prompt, options);

    if (result.action === 'block') {
      throw new PromptInjectionError({
        score: result.score,
        matches: result.matches,
        categories: result.categories,
      });
    }
  };
}

/** Builds a `stripPrompt` that splices matched spans out of the original text. */
export function stripPromptWith(analyze: AnalyzeFn) {
  return function stripPrompt(prompt: PromptInput, options: StripOptions = {}): string {
    const text = resolvePromptInput(prompt, options.analyzeRoles);
    const result = analyze(text, options);

    if (result.matches.length === 0) {
      return text;
    }

    const replacement = options.replacement ?? '';

    const spans = result.matches
      .map((m) => ({ start: m.startIndex, end: m.endIndex }))
      .sort((a, b) => a.start - b.start);

    const merged: Array<{ start: number; end: number }> = [];
    for (const span of spans) {
      const last = merged[merged.length - 1];
      if (last !== undefined && span.start <= last.end) {
        last.end = Math.max(last.end, span.end);
      } else {
        merged.push({ ...span });
      }
    }

    if (options.stripWholeSegment === true) {
      for (const span of merged) {
        let start = span.start;
        let end = span.end;

        while (start > 0 && !/[.\n!?]/.test(text[start - 1] ?? '')) {
          start--;
        }
        while (end < text.length && !/[.\n!?]/.test(text[end] ?? '')) {
          end++;
        }
        if (end < text.length) end++;

        span.start = start;
        span.end = end;
      }
    }

    let result_ = text;
    for (let i = merged.length - 1; i >= 0; i--) {
      const span = merged[i];
      if (span !== undefined) {
        result_ = result_.slice(0, span.start) + replacement + result_.slice(span.end);
      }
    }

    return result_.trim();
  };
}
