import { EXEC_SINKS, EXFIL_SINKS } from './sinks.js';
import type { FailMode } from '../types.js';
import type { GuardPolicy, PolicyAction, PolicyContext } from './types.js';

const SEVERITY: Record<PolicyAction, number> = { allow: 0, flag: 1, confirm: 2, block: 3 };

function flowsFromBlockedSource(ctx: PolicyContext): boolean {
  return ctx.flows.some((f) => ctx.sourceById(f.sourceId)?.injection.action === 'block');
}

/** Exfil sinks are safe when the user named every destination (scenario: "send it to alice"). */
function exfilRisk(ctx: PolicyContext): boolean {
  return EXFIL_SINKS.has(ctx.sink) && !ctx.destinationTrusted;
}

/** Exec runs anything tainted; file-write only cares about payloads and paths. */
function execRisk(ctx: PolicyContext): boolean {
  if (ctx.sink === 'exec') return ctx.flows.length > 0;
  if (ctx.sink !== 'file-write') return false;
  return ctx.flows.some((f) => f.kind !== 'identifier' || f.identifierKind === 'path');
}

export const planViolation: GuardPolicy = {
  id: 'plan-violation',
  evaluate: (ctx) => (ctx.plan !== null && !ctx.plan.has(ctx.call.toolName) ? 'block' : null),
};

export const injectionSourceFlow: GuardPolicy = {
  id: 'injection-source-flow',
  evaluate: (ctx) =>
    (exfilRisk(ctx) || execRisk(ctx)) && flowsFromBlockedSource(ctx) ? 'block' : null,
};

export const untrustedToExfilSink: GuardPolicy = {
  id: 'untrusted-to-exfil-sink',
  evaluate: (ctx) => (exfilRisk(ctx) && ctx.flows.length > 0 ? 'block' : null),
};

export const untrustedToExec: GuardPolicy = {
  id: 'untrusted-to-exec',
  evaluate: (ctx) => (EXEC_SINKS.has(ctx.sink) && execRisk(ctx) ? 'block' : null),
};

export const untrustedToPayment: GuardPolicy = {
  id: 'untrusted-to-payment',
  evaluate: (ctx) => (ctx.sink === 'payment' && ctx.flows.length > 0 ? 'confirm' : null),
};

/** Money moves only with a human in the loop, even when the user named the payee. */
export const paymentConfirm: GuardPolicy = {
  id: 'payment-confirm',
  evaluate: (ctx) => (ctx.sink === 'payment' ? 'confirm' : null),
};

export const injectionThenSink: GuardPolicy = {
  id: 'injection-then-sink',
  evaluate: (ctx) =>
    ctx.sink !== 'none' && ctx.turnSources.some((s) => s.injection.action === 'block') ? 'flag' : null,
};

export const argsInjection: GuardPolicy = {
  id: 'args-injection',
  evaluate: (ctx) => (ctx.sink !== 'none' && ctx.argsAnalysis.action !== 'allow' ? 'flag' : null),
};

/** A confirmed approval exists for this call id but the arguments changed since the card was shown. */
export const approvalMismatch: GuardPolicy = {
  id: 'approval-mismatch',
  evaluate: (ctx) => (ctx.approval?.status === 'mismatch' ? 'block' : null),
};

/** The matching approval expired or was already spent; ask again. */
export const approvalExpired: GuardPolicy = {
  id: 'approval-expired',
  evaluate: (ctx) => (ctx.approval?.status === 'expired' ? 'confirm' : null),
};

/** A value whose lineage reaches a `blocked` source (memory, handoff, derivation) heads for exfil or exec. */
export const lineageUntrusted: GuardPolicy = {
  id: 'lineage-untrusted',
  evaluate: (ctx) =>
    (exfilRisk(ctx) || execRisk(ctx)) && ctx.flows.some((f) => ctx.labelOf(f.sourceId) === 'blocked') ? 'block' : null,
};

export const DEFAULT_POLICIES: readonly GuardPolicy[] = [
  approvalMismatch,
  approvalExpired,
  planViolation,
  injectionSourceFlow,
  lineageUntrusted,
  untrustedToExfilSink,
  untrustedToExec,
  untrustedToPayment,
  paymentConfirm,
  injectionThenSink,
  argsInjection,
];

export interface PolicyOutcome {
  action: PolicyAction;
  /** Ids of policies that fired, most severe first. */
  reasons: string[];
  policy?: string;
}

/**
 * Evaluates every policy; the most severe verdict wins, ties go to list order.
 * A throwing policy blocks under `failMode: 'closed'` and is skipped under `'open'`.
 */
export function evaluatePolicies(
  policies: readonly GuardPolicy[],
  ctx: PolicyContext,
  failMode: FailMode = 'closed',
): PolicyOutcome {
  const fired: Array<{ id: string; action: PolicyAction }> = [];
  for (const policy of policies) {
    let verdict: PolicyAction | null;
    try {
      verdict = policy.evaluate(ctx);
    } catch {
      if (failMode === 'open') continue;
      verdict = 'block';
    }
    if (verdict !== null && verdict !== 'allow') fired.push({ id: policy.id, action: verdict });
  }
  fired.sort((a, b) => SEVERITY[b.action] - SEVERITY[a.action]);
  const top = fired[0];
  if (top === undefined) return { action: 'allow', reasons: [] };
  return { action: top.action, reasons: fired.map((f) => f.id), policy: top.id };
}
