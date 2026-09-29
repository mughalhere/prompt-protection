import {
  approvalExpired,
  approvalMismatch,
  argsInjection,
  budgetExceeded,
  envelopeInvalid,
  handoffUntrusted,
  injectionSourceFlow,
  injectionThenSink,
  lineageUntrusted,
  paymentConfirm,
  planViolation,
  toolDrift,
  toolUnpinned,
  turnUntrustedToUntrustedDestination,
  untrustedToExec,
  untrustedToExfilSink,
  untrustedToPayment,
  DEFAULT_POLICIES,
} from './policy.js';
import type { GuardOptions, GuardPolicy } from './types.js';

export type GuardPreset = 'strict' | 'balanced' | 'permissive';

/** `argsInjection` promoted from flag to block (strict). */
const argsInjectionBlock: GuardPolicy = { id: 'args-injection', evaluate: (ctx) => (argsInjection.evaluate(ctx) === null ? null : 'block') };
/** Payment sinks flag instead of confirm (permissive). */
const paymentFlag: GuardPolicy = { id: 'payment-confirm', evaluate: (ctx) => (paymentConfirm.evaluate(ctx) === null ? null : 'flag') };
const untrustedToPaymentFlag: GuardPolicy = { id: 'untrusted-to-payment', evaluate: (ctx) => (untrustedToPayment.evaluate(ctx) === null ? null : 'flag') };

export const STRICT_POLICIES: readonly GuardPolicy[] = [
  approvalMismatch,
  approvalExpired,
  toolUnpinned,
  toolDrift,
  budgetExceeded,
  planViolation,
  envelopeInvalid,
  handoffUntrusted,
  injectionSourceFlow,
  lineageUntrusted,
  untrustedToExfilSink,
  untrustedToExec,
  untrustedToPayment,
  paymentConfirm,
  turnUntrustedToUntrustedDestination,
  injectionThenSink,
  argsInjectionBlock,
];

export const PERMISSIVE_POLICIES: readonly GuardPolicy[] = [
  approvalMismatch,
  approvalExpired,
  toolUnpinned,
  toolDrift,
  budgetExceeded,
  planViolation,
  envelopeInvalid,
  handoffUntrusted,
  injectionSourceFlow,
  lineageUntrusted,
  untrustedToExfilSink,
  untrustedToExec,
  untrustedToPaymentFlag,
  paymentFlag,
];

/** Option defaults per preset; explicit `GuardOptions` fields always win. */
export const PRESETS: Readonly<Record<GuardPreset, Partial<GuardOptions>>> = {
  balanced: { policies: DEFAULT_POLICIES as GuardPolicy[] },
  strict: {
    policies: STRICT_POLICIES as GuardPolicy[],
    budgets: { maxCallsPerTurn: 20, maxRepeatIdentical: 2, maxDepth: 3 },
    minContainment: 0.4,
  },
  permissive: {
    policies: PERMISSIVE_POLICIES as GuardPolicy[],
    annotationsDefault: 'heuristic',
  },
};

/** Merges a preset under the explicit options; no preset (or `balanced`) leaves the options untouched. */
export function resolvePreset(options: GuardOptions): GuardOptions {
  if (options.preset === undefined) return options;
  const base = PRESETS[options.preset];
  if (base === undefined) throw new TypeError(`unknown guard preset ${String(options.preset)}`);
  const merged: GuardOptions = { ...base, ...options };
  for (const key of Object.keys(options) as Array<keyof GuardOptions>) {
    if (options[key] === undefined) delete (merged as Record<string, unknown>)[key];
  }
  for (const [key, value] of Object.entries(base)) {
    if ((merged as Record<string, unknown>)[key] === undefined) (merged as Record<string, unknown>)[key] = value;
  }
  return merged;
}
