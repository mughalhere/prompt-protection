import { normalizeUnicode } from './utils/unicode.js';
import { decodeObfuscation } from './utils/encoding.js';
import { score } from './scorer.js';
import { OUTPUT_RULES } from './patterns/index.js';
import { computeSeverity } from './api.js';
import type {
  OutputAnalysisOptions,
  OutputAnalysisResult,
  PatternRule,
  ThreatCategory,
} from './types.js';

// Higher than input default (35) to reduce false positives, but low enough
// that a single high-confidence match (weight 10 → score ~49) still triggers.
const DEFAULT_OUTPUT_THRESHOLD = 40;

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
  const rules = buildOutputRuleSet(options);

  const normalized = normalizeOutput(output);
  const { normalizedScore, matches } = score(rules, normalized, output);

  const threats = [...new Set(matches.map((m) => m.rule.category))] as ThreatCategory[];

  return {
    score: normalizedScore,
    severity: computeSeverity(normalizedScore),
    isSuspicious: normalizedScore >= threshold,
    matches,
    threats,
  };
}
