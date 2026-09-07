import { verifyPrompt } from '../api.js';
import { analyzeOutput } from '../output.js';
import type { LanguageModelMiddleware } from 'ai';
import type { VerifyOptions, OutputAnalysisOptions } from '../types.js';

export interface PromptProtectionMiddlewareOptions extends VerifyOptions {
  /**
   * Also scan the model's generated text and throw if it is blocked
   * (system-prompt leak, credential exposure, injection relay, PII).
   * Default: false.
   */
  scanOutput?: boolean;
  /** Options for the output scan when `scanOutput` is true. */
  outputOptions?: OutputAnalysisOptions;
}

/**
 * Pulls the user-authored text out of a Vercel AI SDK v4/v5 prompt so it can be
 * scanned. System/assistant turns are skipped; only untrusted user content is
 * checked, matching the library's default role policy.
 */
function extractUserText(prompt: unknown): string {
  if (!Array.isArray(prompt)) return '';
  const chunks: string[] = [];
  for (const message of prompt as Array<{ role?: string; content?: unknown }>) {
    if (message.role !== 'user') continue;
    const content = message.content;
    if (typeof content === 'string') {
      chunks.push(content);
    } else if (Array.isArray(content)) {
      for (const part of content as Array<{ type?: string; text?: string }>) {
        if (part.type === 'text' && typeof part.text === 'string') chunks.push(part.text);
      }
    }
  }
  return chunks.join('\n');
}

/**
 * Vercel AI SDK middleware that blocks malicious prompts before the model call.
 *
 * @example
 * import { wrapLanguageModel } from 'ai';
 * import { promptProtectionMiddleware } from 'prompt-protection/adapters/vercel';
 *
 * const model = wrapLanguageModel({
 *   model: openai('gpt-4o'),
 *   middleware: promptProtectionMiddleware({ threshold: 40 }),
 * });
 *
 * `transformParams` runs `verifyPrompt` on the user text and throws
 * `PromptInjectionError` on a block, rejecting the generate/stream call. With
 * `scanOutput`, `wrapGenerate` additionally scans the completion.
 */
export function promptProtectionMiddleware(
  options: PromptProtectionMiddlewareOptions = {},
): LanguageModelMiddleware {
  const { scanOutput, outputOptions, ...verifyOptions } = options;

  const middleware: LanguageModelMiddleware = {
    transformParams: ({ params }) => {
      const text = extractUserText((params as { prompt?: unknown }).prompt);
      if (text.length > 0) verifyPrompt(text, verifyOptions);
      return Promise.resolve(params);
    },
  };

  if (scanOutput) {
    middleware.wrapGenerate = async ({ doGenerate }) => {
      const result = await doGenerate();
      const parts = Array.isArray(result.content) ? result.content : [];
      const text = parts
        .filter((p): p is { type: 'text'; text: string } => (p as { type?: string }).type === 'text')
        .map((p) => p.text)
        .join('\n');
      if (text.length > 0) {
        const scan = analyzeOutput(text, outputOptions);
        if (scan.action === 'block') {
          throw new Error(
            `prompt-protection: model output blocked (score ${scan.score}, ${scan.threats.join(', ')})`,
          );
        }
      }
      return result;
    };
  }

  return middleware;
}
