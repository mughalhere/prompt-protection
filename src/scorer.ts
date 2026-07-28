import type { PatternMatch, PatternRule } from './types.js';

export interface ScoreResult {
  rawScore: number;
  /** 0–100, using exponential normalisation: 100 * (1 - e^(-raw/15)) */
  normalizedScore: number;
  matches: PatternMatch[];
}

export interface ScoreOptions {
  /** Maps normalized indices back to original string indices */
  indexMap?: number[];
  /** Spans matching these patterns are excluded from scoring */
  allowlistPatterns?: RegExp[];
  /** Rule IDs whose matches are excluded from scoring */
  allowlistRuleIds?: string[];
}

interface Span {
  start: number;
  end: number;
}

function collectAllowlistSpans(text: string, patterns: RegExp[] | undefined): Span[] {
  if (!patterns || patterns.length === 0) return [];

  const spans: Span[] = [];
  for (const pattern of patterns) {
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
      spans.push({ start: match.index, end: match.index + match[0].length });
      if (match[0].length === 0) {
        re.lastIndex++;
      }
    }
  }
  return spans;
}

function spansOverlap(a: Span, b: Span): boolean {
  return a.start < b.end && b.start < a.end;
}

function isAllowlisted(
  matchSpan: Span,
  allowlistSpans: Span[],
  ruleId: string,
  allowlistedRuleIds: Set<string>,
): boolean {
  if (allowlistedRuleIds.has(ruleId)) return true;
  return allowlistSpans.some((s) => spansOverlap(matchSpan, s));
}

function mapIndex(indexMap: number[] | undefined, normalizedIndex: number, fallbackLength: number): number {
  if (indexMap && indexMap.length > 0) {
    const mapped = indexMap[Math.min(normalizedIndex, indexMap.length - 1)];
    if (mapped !== undefined) return mapped;
  }
  return Math.min(normalizedIndex, Math.max(fallbackLength - 1, 0));
}

/**
 * Runs all rules against the normalized text and computes a weighted score.
 * Diminishing returns: repeated hits from the same rule ID add only 25% of weight.
 * Allowlisted spans / rule IDs are excluded from both matches and score.
 */
export function score(
  rules: PatternRule[],
  normalizedText: string,
  originalText: string,
  options: ScoreOptions = {},
): ScoreResult {
  const matches: PatternMatch[] = [];
  const hitCounts = new Map<string, number>();
  const allowlistSpans = collectAllowlistSpans(normalizedText, options.allowlistPatterns);
  const allowlistedRuleIds = new Set(options.allowlistRuleIds ?? []);

  for (const rule of rules) {
    const re = new RegExp(rule.pattern.source, 'gi');
    let match: RegExpExecArray | null;

    while ((match = re.exec(normalizedText)) !== null) {
      const normStart = match.index;
      const normEnd = match.index + match[0].length;

      if (
        isAllowlisted(
          { start: normStart, end: normEnd },
          allowlistSpans,
          rule.id,
          allowlistedRuleIds,
        )
      ) {
        continue;
      }

      const hitCount = hitCounts.get(rule.id) ?? 0;
      hitCounts.set(rule.id, hitCount + 1);

      const startIndex = mapIndex(options.indexMap, normStart, originalText.length);
      const endMapped = mapIndex(options.indexMap, Math.max(normEnd - 1, normStart), originalText.length);
      const endIndex = Math.min(endMapped + 1, originalText.length);

      matches.push({
        rule,
        matchedText: originalText.slice(startIndex, endIndex),
        startIndex,
        endIndex,
      });
    }
  }

  let rawScore = 0;
  const seenRuleHits = new Map<string, number>();

  for (const m of matches) {
    const seen = seenRuleHits.get(m.rule.id) ?? 0;
    seenRuleHits.set(m.rule.id, seen + 1);
    rawScore += seen === 0 ? m.rule.weight : m.rule.weight * 0.25;
  }

  const normalizedScore = Math.round(100 * (1 - Math.exp(-rawScore / 15)));

  return { rawScore, normalizedScore, matches };
}
