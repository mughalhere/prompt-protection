// Internal: shared by the framework `protect()` adapters. Not a subpath.
import type { FailMode } from '../types.js';
import type { GuardDecision } from '../guard/types.js';

export interface Denial {
  code: string;
  message: string;
}

/** The one-line reason a framework surfaces when the guard refuses a call. */
export function denial(decision: GuardDecision): Denial {
  const code = decision.policy ?? decision.reasons[0] ?? 'blocked';
  const flows = decision.flows.length > 0 ? `; tainted: ${[...new Set(decision.flows.map((f) => `${f.path} from ${f.sourceTool}`))].join(', ')}` : '';
  const verdict = decision.requiresConfirmation ? 'needs approval' : 'denied';
  return { code, message: `prompt-protection: ${decision.toolName} ${verdict} (${code}; sink ${decision.sink}${flows})` };
}

/**
 * Runs a hook under the guard's fail mode: a throwing hook yields `closed(err)` (deny) or
 * `open(err)` (pass-through), never an unhandled rejection in the host loop.
 */
export async function guarded<T>(
  fn: () => Promise<T> | T,
  failMode: FailMode,
  fallback: { closed: (err: unknown) => T; open: (err: unknown) => T },
): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    return failMode === 'open' ? fallback.open(err) : fallback.closed(err);
  }
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
