import type { AnyString } from '../types.js';

/**
 * Stable reason codes carried in `GuardDecision.reasons`. Default policy ids are reason codes;
 * codes marked 4.2–4.4 are reserved so consumers can switch on them today.
 */
export type DecisionReason =
  | 'plan-violation'
  | 'injection-source-flow'
  | 'untrusted-to-exfil-sink'
  | 'untrusted-to-exec'
  | 'untrusted-to-payment'
  | 'payment-confirm'
  | 'injection-then-sink'
  | 'args-injection'
  | 'approval-mismatch'
  | 'approval-expired'
  | 'approved'
  | 'lineage-untrusted'
  | 'handoff-untrusted'
  | 'tool-unpinned' // 4.2
  | 'tool-drift' // 4.2
  | 'budget-exceeded' // 4.2
  | 'envelope-invalid' // 4.4
  | 'internal-error'
  | AnyString; // open union, see docs/API_STABILITY.md

/** Every code a 4.1 guard can emit. Drives the dataset validator and the steps interpreter. */
export const DECISION_REASONS: readonly DecisionReason[] = [
  'plan-violation',
  'injection-source-flow',
  'untrusted-to-exfil-sink',
  'untrusted-to-exec',
  'untrusted-to-payment',
  'payment-confirm',
  'injection-then-sink',
  'args-injection',
  'approval-mismatch',
  'approval-expired',
  'approved',
  'lineage-untrusted',
  'tool-unpinned',
  'tool-drift',
  'budget-exceeded',
  'internal-error',
];

const KNOWN: ReadonlySet<string> = new Set(DECISION_REASONS);

export function isDecisionReason(value: string): boolean {
  return KNOWN.has(value);
}
