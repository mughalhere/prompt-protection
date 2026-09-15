import { computeSeverity } from '../core/analyze.js';
import type {
  AnalysisResult,
  MlContribution,
  MlMode,
  PatternMatch,
  PatternRule,
  ThreatCategory,
} from '../types.js';
import type { ClassifierMeta } from './types.js';

export const ML_RULE_ID = 'ml-injection-classifier';
const MATCHED_TEXT_CHARS = 80;
const WEAK_BLOCK_MARGIN = 15;

const ML_BLOCK_RULE: PatternRule = {
  id: ML_RULE_ID,
  category: 'prompt-injection',
  pattern: /(?!)/, // never matches text; synthetic matches only
  weight: 10,
  precision: 'high',
  description: 'Embedded classifier scored the input as a prompt injection',
};

const ML_FLAG_RULE: PatternRule = { ...ML_BLOCK_RULE, weight: 5, precision: 'low' };

function syntheticMatch(rule: PatternRule, text: string): PatternMatch {
  return { rule, matchedText: text.slice(0, MATCHED_TEXT_CHARS), startIndex: 0, endIndex: 0 };
}

function withMatch(result: AnalysisResult, match: PatternMatch): Pick<AnalysisResult, 'matches' | 'categories'> {
  return {
    matches: [...result.matches, match],
    categories: [...new Set([...result.categories, match.rule.category])] as ThreatCategory[],
  };
}

/** A block held up by one category, no high-precision rule, and a score near the threshold. */
function isWeakBlock(result: AnalysisResult, threshold: number): boolean {
  return (
    result.categories.length === 1 &&
    !result.matches.some((m) => m.rule.precision === 'high') &&
    result.score < threshold + WEAK_BLOCK_MARGIN
  );
}

/**
 * Merges the classifier probability into the rules verdict. `escalate` only
 * raises the action; `hybrid` may also downgrade a weak block to `flag`.
 * `text` is the original prompt used for the synthetic match preview.
 */
export function fuseVerdict(
  ruleResult: AnalysisResult,
  probability: number,
  mode: MlMode,
  meta: ClassifierMeta,
  threshold: number,
  text: string = ruleResult.normalizedPrompt,
): AnalysisResult {
  if (mode === 'off') return ruleResult;

  const { flag, block, benign } = meta.thresholds;
  const ml = (contributed: MlContribution['contributed']): MlContribution => ({ probability, contributed });

  if (probability >= block && ruleResult.action !== 'block') {
    const score = Math.max(ruleResult.score, threshold);
    return {
      ...ruleResult,
      ...withMatch(ruleResult, syntheticMatch(ML_BLOCK_RULE, text)),
      score,
      severity: computeSeverity(score),
      action: 'block',
      isMalicious: true,
      ml: ml('escalated'),
    };
  }

  if (probability >= flag && probability < block && ruleResult.action === 'allow') {
    return {
      ...ruleResult,
      ...withMatch(ruleResult, syntheticMatch(ML_FLAG_RULE, text)),
      action: 'flag',
      isMalicious: false,
      ml: ml('flagged'),
    };
  }

  if (
    mode === 'hybrid' &&
    probability <= benign &&
    ruleResult.action === 'block' &&
    isWeakBlock(ruleResult, threshold)
  ) {
    return { ...ruleResult, action: 'flag', isMalicious: false, ml: ml('downgraded') };
  }

  return { ...ruleResult, ml: ml('none') };
}
