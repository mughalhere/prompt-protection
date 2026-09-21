import type { FlowSummary } from '../types.js';
import type { DecisionReason } from './reasons.js';
import type { GuardDecision } from './types.js';

export interface ExplainStep {
  code: DecisionReason;
  /** The policy that carries this code, when it is a policy id. */
  policy?: string;
  because: string;
  flows: FlowSummary[];
}

export interface Explanation {
  summary: string;
  chain: ExplainStep[];
}

const BECAUSE: Record<string, (d: GuardDecision) => string> = {
  'plan-violation': (d) => `${d.toolName} is not in the plan() allow-list for this turn`,
  'injection-source-flow': (d) => `a source that itself scored as injection flows into ${d.toolName}`,
  'untrusted-to-exfil-sink': (d) => `untrusted data reaches an exfil sink (${d.sink}) and the user did not name every destination`,
  'untrusted-to-exec': (d) => `untrusted data reaches an execution sink (${d.sink})`,
  'untrusted-to-payment': () => 'untrusted data reaches a payment sink; a human must confirm',
  'payment-confirm': () => 'money moves only with a human in the loop',
  'injection-then-sink': () => 'a source this turn scored as injection and the call targets a sink, even without a detected flow',
  'args-injection': () => 'the tool-call arguments themselves read as injection',
  'approval-mismatch': () => 'a confirmed approval exists for this call id but the arguments changed since the card was shown',
  'approval-expired': () => 'the matching approval expired or was already spent; ask again',
  approved: () => 'a human approved these exact arguments; the confirm was cleared once',
  'lineage-untrusted': () => 'a value whose lineage reaches a blocked source (memory, handoff, derivation) heads for exfil or exec',
  'handoff-untrusted': () => 'the parent handoff could not be verified, so its sources are treated as blocked',
  'tool-unpinned': (d) =>
    d.lock?.locked === true ? `${d.toolName} is not in the tool lock` : 'requireLock is set and no lock is installed',
  'tool-drift': (d) => `the pinned definition of ${d.toolName} changed (${d.lock?.drift?.kind ?? 'changed'})`,
  'budget-exceeded': (d) => `budget exceeded: ${(d.budget?.exceeded ?? []).join(', ') || 'a configured limit'}`,
  'envelope-invalid': () => 'a sealed envelope failed verification, so its payload is treated as blocked',
  'internal-error': () => 'the guard itself threw; the verdict comes from failMode',
};

function summaryOf(d: GuardDecision): string {
  const verdict = d.requiresConfirmation ? 'confirm' : d.action;
  const sink = d.sink === 'none' ? 'no sink' : `sink ${d.sink}`;
  const lock = d.lock?.locked ? ', locked' : '';
  const observed = d.observedAction !== undefined ? ` (observe mode; enforced verdict would be ${d.observedRequiresConfirmation ? 'confirm' : d.observedAction})` : '';
  const top = d.reasons[0];
  return `${verdict} ${d.toolName} (${sink}${lock}, depth ${d.depth})${top !== undefined ? `: ${top}` : ''}${observed}`;
}

/** One step per reason code, in decision order; unknown codes (future minors) get a generic line. */
export function explain(decision: GuardDecision): Explanation {
  const flows: FlowSummary[] = decision.flows.map((f) => ({ kind: f.kind, sourceId: f.sourceId, sourceTool: f.sourceTool, path: f.path, strength: f.strength }));
  const chain: ExplainStep[] = decision.reasons.map((code) => {
    const because = BECAUSE[code]?.(decision) ?? `policy or check "${code}" fired`;
    const isPolicy = code !== 'approved';
    return { code, ...(isPolicy ? { policy: code } : {}), because, flows: isPolicy ? flows : [] };
  });
  return { summary: summaryOf(decision), chain };
}
