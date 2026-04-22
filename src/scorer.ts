import type { PatternMatch, PatternRule } from './types.js';

export interface ScoreResult {
  rawScore: number;
  /** 0–100, using exponential normalisation: 100 * (1 - e^(-raw/15)) */
  normalizedScore: number;
  matches: PatternMatch[];
}

/**
 * Runs all rules against the normalized text and computes a weighted score.
 * Diminishing returns: repeated hits from the same rule ID add only 25% of weight.
 */
export function score(rules: PatternRule[], normalizedText: string, originalText: string): ScoreResult {
  const matches: PatternMatch[] = [];
  const hitCounts = new Map<string, number>();

  for (const rule of rules) {
    const re = new RegExp(rule.pattern.source, 'gi');
    let match: RegExpExecArray | null;

    while ((match = re.exec(normalizedText)) !== null) {
      const hitCount = hitCounts.get(rule.id) ?? 0;
      hitCounts.set(rule.id, hitCount + 1);

      // Map normalized position back to original string position
      const startIndex = Math.min(match.index, originalText.length - 1);
      const endIndex = Math.min(match.index + match[0].length, originalText.length);

      matches.push({
        rule,
        matchedText: originalText.slice(startIndex, endIndex),
        startIndex,
        endIndex,
      });
    }
  }

  // Compute raw score with diminishing returns per rule
  let rawScore = 0;
  const seenRuleHits = new Map<string, number>();

  for (const m of matches) {
    const seen = seenRuleHits.get(m.rule.id) ?? 0;
    seenRuleHits.set(m.rule.id, seen + 1);
    // First hit: full weight. Subsequent hits: 25% of weight each.
    rawScore += seen === 0 ? m.rule.weight : m.rule.weight * 0.25;
  }

  // Exponential normalisation: asymptotes at 100, reaches ~50 at rawScore≈10.4
  const normalizedScore = Math.round(100 * (1 - Math.exp(-rawScore / 15)));

  return { rawScore, normalizedScore, matches };
}
