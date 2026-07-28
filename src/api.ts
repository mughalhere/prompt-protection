import { normalize } from './normalizer.js';
import { score } from './scorer.js';
import { ALL_RULES } from './patterns/index.js';
import { PromptInjectionError } from './error.js';
import { resolvePromptInput } from './messages.js';
import { resolveAction } from './verdict.js';
import { emitInputLog } from './logging.js';
import type {
  AnalysisResult,
  AnalyzeOptions,
  PatternRule,
  PromptInput,
  SeverityLevel,
  StripOptions,
  ThreatCategory,
  VerifyOptions,
} from './types.js';

const DEFAULT_THRESHOLD = 35;

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

function buildRuleSet(options: AnalyzeOptions): PatternRule[] {
  let rules = [...ALL_RULES];

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

export function analyzePrompt(prompt: PromptInput, options: AnalyzeOptions = {}): AnalysisResult {
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const rules = buildRuleSet(options);
  const text = resolvePromptInput(prompt, options.analyzeRoles);

  const { normalized, indexMap } = normalize(text);
  const { normalizedScore, matches } = score(rules, normalized, text, {
    indexMap,
    ...(options.allowlistPatterns ? { allowlistPatterns: options.allowlistPatterns } : {}),
    ...(options.allowlistRuleIds ? { allowlistRuleIds: options.allowlistRuleIds } : {}),
  });

  const categories = [...new Set(matches.map((m) => m.rule.category))] as ThreatCategory[];
  const action = resolveAction(normalizedScore, matches, threshold, options.flagThreshold);

  const result: AnalysisResult = {
    score: normalizedScore,
    severity: computeSeverity(normalizedScore),
    isMalicious: action === 'block',
    action,
    matches,
    categories,
    normalizedPrompt: normalized,
  };

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
}

export function verifyPrompt(prompt: PromptInput, options: VerifyOptions = {}): void {
  const result = analyzePrompt(prompt, options);

  if (result.action === 'block') {
    throw new PromptInjectionError({
      score: result.score,
      matches: result.matches,
      categories: result.categories,
    });
  }
}

export function stripPrompt(prompt: PromptInput, options: StripOptions = {}): string {
  const text = resolvePromptInput(prompt, options.analyzeRoles);
  const result = analyzePrompt(text, options);

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
}
