import { normalize } from './normalizer.js';
import { score } from './scorer.js';
import { ALL_RULES } from './patterns/index.js';
import { PromptInjectionError } from './error.js';
import type {
  AnalysisResult,
  AnalyzeOptions,
  PatternRule,
  StripOptions,
  ThreatCategory,
  VerifyOptions,
} from './types.js';

const DEFAULT_THRESHOLD = 35;

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

export function analyzePrompt(prompt: string, options: AnalyzeOptions = {}): AnalysisResult {
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const rules = buildRuleSet(options);

  const { normalized } = normalize(prompt);
  const { normalizedScore, matches } = score(rules, normalized, prompt);

  const categories = [...new Set(matches.map((m) => m.rule.category))] as ThreatCategory[];

  return {
    score: normalizedScore,
    isMalicious: normalizedScore >= threshold,
    matches,
    categories,
    normalizedPrompt: normalized,
  };
}

export function verifyPrompt(prompt: string, options: VerifyOptions = {}): void {
  const result = analyzePrompt(prompt, options);

  if (result.isMalicious) {
    throw new PromptInjectionError({
      score: result.score,
      matches: result.matches,
      categories: result.categories,
    });
  }
}

export function stripPrompt(prompt: string, options: StripOptions = {}): string {
  const result = analyzePrompt(prompt, options);

  if (result.matches.length === 0) {
    return prompt;
  }

  const replacement = options.replacement ?? '';

  // Sort matches by start index, then merge overlapping spans
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
      // Expand to surrounding sentence boundary
      let start = span.start;
      let end = span.end;

      while (start > 0 && !/[.\n!?]/.test(prompt[start - 1] ?? '')) {
        start--;
      }
      while (end < prompt.length && !/[.\n!?]/.test(prompt[end] ?? '')) {
        end++;
      }
      if (end < prompt.length) end++;

      span.start = start;
      span.end = end;
    }
  }

  // Replace spans in reverse order to preserve indices
  let result_ = prompt;
  for (let i = merged.length - 1; i >= 0; i--) {
    const span = merged[i];
    if (span !== undefined) {
      result_ = result_.slice(0, span.start) + replacement + result_.slice(span.end);
    }
  }

  return result_.trim();
}
