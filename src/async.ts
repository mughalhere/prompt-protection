import { analyzePrompt } from './api.js';
import { PromptInjectionError } from './error.js';
import { resolvePromptInput } from './messages.js';
import type { AsyncVerifyOptions, PromptInput } from './types.js';

/**
 * Sync `block` always wins. The adapter may only escalate:
 * - allow → block (adapter says malicious)
 * - flag → block (adapter says malicious)
 * Adapter cannot override a sync block to safe.
 */
export async function verifyPromptAsync(
  prompt: PromptInput,
  options: AsyncVerifyOptions,
): Promise<void> {
  const syncResult = analyzePrompt(prompt, options);
  const text = resolvePromptInput(prompt, options.analyzeRoles);

  // Sync block is authoritative — never let the adapter downgrade it
  if (syncResult.action === 'block') {
    throw new PromptInjectionError({
      score: syncResult.score,
      matches: syncResult.matches,
      categories: syncResult.categories,
    });
  }

  let adapterResult: { isMalicious: boolean; reason?: string } | null = null;

  try {
    adapterResult = await options.adapter.analyze(text);
  } catch (err) {
    if (options.fallbackToSync === true) {
      adapterResult = null;
    } else {
      throw err;
    }
  }

  // Adapter can only escalate allow/flag → block
  const escalate = adapterResult !== null && adapterResult.isMalicious;

  if (escalate) {
    throw new PromptInjectionError({
      score: syncResult.score,
      matches: syncResult.matches,
      categories: syncResult.categories,
    });
  }
}
