import type { Action, PatternMatch, RulePrecision } from './types.js';

function rulePrecision(match: PatternMatch): RulePrecision {
  return match.rule.precision ?? 'medium';
}

/**
 * Block requires score ≥ threshold and either:
 * - at least one high/medium precision match, or
 * - ≥2 distinct threat categories
 *
 * Lone low-precision matches cannot alone produce block.
 */
export function precisionAllowsBlock(matches: PatternMatch[]): boolean {
  if (matches.length === 0) return false;

  const hasNonLow = matches.some((m) => rulePrecision(m) !== 'low');
  if (hasNonLow) return true;

  const categories = new Set(matches.map((m) => m.rule.category));
  return categories.size >= 2;
}

/**
 * Resolve three-way action from score, matches, and thresholds.
 *
 * - When `flagThreshold` is omitted: only `allow` | `block` (unless precision
 *   downgrades a would-be block to `flag`).
 * - When set: `flagThreshold <= score < threshold` → `flag`.
 */
export function resolveAction(
  score: number,
  matches: PatternMatch[],
  threshold: number,
  flagThreshold?: number,
): Action {
  const wouldBlock = score >= threshold;

  if (wouldBlock) {
    // Empty matches + threshold 0 (or similar) — preserve legacy "everything blocked" behaviour
    if (matches.length === 0 || precisionAllowsBlock(matches)) {
      return 'block';
    }
    return 'flag';
  }

  if (flagThreshold !== undefined && score >= flagThreshold) {
    return 'flag';
  }

  return 'allow';
}
