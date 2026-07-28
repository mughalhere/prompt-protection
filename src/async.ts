import { analyzePrompt } from './api.js';
import { PromptInjectionError } from './error.js';
import { resolvePromptInput } from './messages.js';
import type { AsyncVerifyOptions, PromptInput } from './types.js';

export async function verifyPromptAsync(
  prompt: PromptInput,
  options: AsyncVerifyOptions,
): Promise<void> {
  const syncResult = analyzePrompt(prompt, options);
  const text = resolvePromptInput(prompt, options.analyzeRoles);

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

  const isMalicious = adapterResult !== null ? adapterResult.isMalicious : syncResult.isMalicious;

  if (isMalicious) {
    throw new PromptInjectionError({
      score: syncResult.score,
      matches: syncResult.matches,
      categories: syncResult.categories,
    });
  }
}
