import { analyzePrompt } from './api.js';
import { PromptInjectionError } from './error.js';
import type { AsyncVerifyOptions } from './types.js';

export async function verifyPromptAsync(
  prompt: string,
  options: AsyncVerifyOptions,
): Promise<void> {
  const syncResult = analyzePrompt(prompt, options);

  let adapterResult: { isMalicious: boolean; reason?: string } | null = null;

  try {
    adapterResult = await options.adapter.analyze(prompt);
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
