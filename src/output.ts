import { normalizeUnicode } from './utils/unicode.js';
import { decodeObfuscation } from './utils/encoding.js';
import { score } from './scorer.js';
import { OUTPUT_RULES } from './patterns/index.js';
import { computeSeverity, failedAnalysis } from './core/analyze.js';
import { resolveAction } from './verdict.js';
import { emitOutputLog } from './logging.js';
import {
  detectCanary,
  promptSimilarity,
  SIMILARITY_CONTAINMENT_THRESHOLD,
  SIMILARITY_RUN_THRESHOLD,
} from './canary/index.js';
import type {
  CanaryDetection,
  OutputAnalysisOptions,
  OutputAnalysisResult,
  PatternMatch,
  PatternRule,
  ThreatCategory,
} from './types.js';

// Higher than input default (35) to reduce false positives, but low enough
// that a single high-confidence match (weight 10 → score ~49) still triggers.
const DEFAULT_OUTPUT_THRESHOLD = 40;
const DEFAULT_MAX_INPUT_LENGTH = 100_000;

// Synthetic rules (never match text; see session.ts CORRELATION_RULE precedent).
const CANARY_LEAK_RULE: PatternRule = {
  id: 'out-canary-leak',
  category: 'system-prompt-leak',
  pattern: /(?!)/,
  weight: 10,
  precision: 'high',
  description: 'Canary token injected into the system prompt appears in the output',
};

const PROMPT_SIMILARITY_RULE: PatternRule = {
  id: 'out-system-prompt-similarity',
  category: 'system-prompt-leak',
  pattern: /(?!)/,
  weight: 8,
  precision: 'medium',
  description: 'Output reproduces a substantial verbatim portion of the system prompt',
};

function syntheticMatch(rule: PatternRule, matchedText: string): PatternMatch {
  return { rule, matchedText, startIndex: 0, endIndex: 0 };
}

/**
 * Runs canary + system-prompt similarity when configured. Returns the
 * detection plus the synthetic matches it justifies (appended to `matches`
 * before verdict resolution so `action` and `isSuspicious` stay consistent).
 */
function detectLeaks(
  output: string,
  options: OutputAnalysisOptions,
): { canary: CanaryDetection; synthetic: PatternMatch[] } | null {
  if (options.canary === undefined && options.systemPrompt === undefined) return null;

  const canary: CanaryDetection =
    options.canary !== undefined
      ? detectCanary(output, options.canary)
      : { leaked: false, confidence: 0, variants: [] };
  if (options.systemPrompt !== undefined) {
    canary.promptSimilarity = promptSimilarity(output, options.systemPrompt);
  }

  const synthetic: PatternMatch[] = [];
  if (canary.leaked) {
    synthetic.push(syntheticMatch(CANARY_LEAK_RULE, canary.variants.join(',')));
  }
  const sim = canary.promptSimilarity;
  if (
    sim &&
    (sim.containment >= SIMILARITY_CONTAINMENT_THRESHOLD || sim.longestRun >= SIMILARITY_RUN_THRESHOLD)
  ) {
    synthetic.push(
      syntheticMatch(
        PROMPT_SIMILARITY_RULE,
        `containment=${sim.containment.toFixed(2)} run=${sim.longestRun}`,
      ),
    );
  }
  return { canary, synthetic };
}

function rescore(rawScore: number, synthetic: PatternMatch[]): number {
  const raw = synthetic.reduce((acc, m) => acc + m.rule.weight, rawScore);
  return Math.round(100 * (1 - Math.exp(-raw / 15)));
}

/**
 * Normalizes output text for scanning without applying the homoglyph digit→letter
 * substitution used for input analysis. Output scanning needs real digits intact
 * so that patterns for API keys, SSNs, and credit card numbers can match.
 */
function normalizeOutput(text: string): string {
  const afterUnicode = normalizeUnicode(text);
  const afterDecoding = decodeObfuscation(afterUnicode);
  return afterDecoding.toLowerCase();
}

function buildOutputRuleSet(options: OutputAnalysisOptions): PatternRule[] {
  let rules = [...OUTPUT_RULES];

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
 * Scans LLM output for signs of compromise: system prompt leakage,
 * credential exposure, injection relay, and PII exposure.
 */
export function analyzeOutput(
  output: string,
  options: OutputAnalysisOptions = {},
): OutputAnalysisResult {
  const threshold = options.threshold ?? DEFAULT_OUTPUT_THRESHOLD;
  try {
  const rules = buildOutputRuleSet(options);

  const cap = options.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
  const capped = output.length > cap ? output.slice(0, cap) : output;
  const normalized = normalizeOutput(capped);
  const scored = score(rules, normalized, capped, {
    ...(options.allowlistPatterns ? { allowlistPatterns: options.allowlistPatterns } : {}),
    ...(options.allowlistRuleIds ? { allowlistRuleIds: options.allowlistRuleIds } : {}),
  });

  const leaks = detectLeaks(capped, options);
  const matches = leaks ? [...scored.matches, ...leaks.synthetic] : scored.matches;
  const normalizedScore =
    leaks && leaks.synthetic.length > 0
      ? rescore(scored.rawScore, leaks.synthetic)
      : scored.normalizedScore;

  const threats = [...new Set(matches.map((m) => m.rule.category))] as ThreatCategory[];
  const action = resolveAction(normalizedScore, matches, threshold, options.flagThreshold);

  const result: OutputAnalysisResult = {
    score: normalizedScore,
    severity: computeSeverity(normalizedScore),
    isSuspicious: action === 'flag' || action === 'block',
    action,
    matches,
    threats,
  };
  if (leaks) result.canary = leaks.canary;

  emitOutputLog(result, output, options);

  return result;
  } catch (err) {
    const failed = failedAnalysis(err, options.failMode ?? 'closed', threshold);
    const result: OutputAnalysisResult = {
      score: failed.score,
      severity: failed.severity,
      isSuspicious: failed.action !== 'allow',
      action: failed.action,
      matches: failed.matches,
      threats: [],
      ...(failed.error ? { error: failed.error } : {}),
    };
    emitOutputLog(result, output, options);
    return result;
  }
}
