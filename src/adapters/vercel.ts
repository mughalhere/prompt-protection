import { verifyPrompt } from '../api.js';
import { analyzeOutput } from '../output.js';
import { ToolCallBlockedError } from '../guard/errors.js';
import type { Guard, GuardDecision } from '../guard/types.js';
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
  /**
   * Tool-call guard. Tool results in the prompt are tainted on the way in;
   * tool calls in the response are checked on the way out. The middleware
   * sees calls but cannot stop the SDK executing them, so pair it with
   * `tools: guard.wrapTools(tools)` or `toolApproval: guard.vercelToolApproval()`.
   */
  guard?: Guard;
  /** What to do with a blocked tool call: replace it with a refusal text part, or throw. Default: 'refuse'. */
  onBlock?: 'refuse' | 'throw';
}

interface ToolResultPart {
  type?: string;
  toolCallId?: string;
  toolName?: string;
  output?: { type?: string; value?: unknown };
  result?: unknown;
}

interface ToolCallPart {
  type?: string;
  toolCallId?: string;
  toolName?: string;
  input?: unknown;
  args?: unknown;
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

/** Registers every `tool-result` part of the prompt as an untrusted source. */
function taintToolResults(prompt: unknown, guard: Guard): void {
  if (!Array.isArray(prompt)) return;
  for (const message of prompt as Array<{ role?: string; content?: unknown }>) {
    if (message.role !== 'tool' || !Array.isArray(message.content)) continue;
    for (const part of message.content as ToolResultPart[]) {
      if (part.type !== 'tool-result') continue;
      const value = part.output !== undefined ? part.output.value : part.result;
      const name = part.toolName ?? 'tool';
      guard.taint(name, value, part.toolCallId !== undefined ? { id: part.toolCallId } : {});
    }
  }
}

function parseArgs(part: ToolCallPart): unknown {
  const raw = part.input !== undefined ? part.input : part.args;
  if (typeof raw !== 'string') return raw ?? {};
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
}

function checkPart(part: ToolCallPart, guard: Guard): GuardDecision {
  return guard.checkToolCall({
    toolName: part.toolName ?? 'tool',
    args: parseArgs(part),
    ...(part.toolCallId !== undefined ? { toolCallId: part.toolCallId } : {}),
  });
}

function refusalText(decision: GuardDecision): string {
  const why = decision.policy ?? decision.reasons[0] ?? 'policy';
  return `[prompt-protection] Tool call \`${decision.toolName}\` was blocked (${why}).`;
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
 * `scanOutput`, `wrapGenerate` additionally scans the completion. With `guard`,
 * tool results are tainted and proposed tool calls are checked (advisory , 
 * enforce with `guard.wrapTools` / `guard.vercelToolApproval`).
 */
export function promptProtectionMiddleware(
  options: PromptProtectionMiddlewareOptions = {},
): LanguageModelMiddleware {
  const { scanOutput, outputOptions, guard, onBlock = 'refuse', ...verifyOptions } = options;

  const middleware: LanguageModelMiddleware = {
    transformParams: ({ params }) => {
      const prompt = (params as { prompt?: unknown }).prompt;
      if (guard) taintToolResults(prompt, guard);
      const text = extractUserText(prompt);
      if (text.length > 0) verifyPrompt(text, verifyOptions);
      return Promise.resolve(params);
    },
  };

  if (scanOutput || guard) {
    middleware.wrapGenerate = async ({ doGenerate }) => {
      const result = await doGenerate();
      const parts: unknown[] = Array.isArray(result.content) ? [...result.content] : [];

      if (guard) {
        for (let i = 0; i < parts.length; i++) {
          const part = parts[i] as ToolCallPart;
          if (part.type !== 'tool-call') continue;
          const decision = checkPart(part, guard);
          if (decision.action !== 'block') continue;
          if (onBlock === 'throw') throw new ToolCallBlockedError(decision);
          parts[i] = { type: 'text', text: refusalText(decision) };
        }
      }

      if (scanOutput) {
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
      }

      return guard ? { ...result, content: parts as typeof result.content } : result;
    };
  }

  if (guard) {
    middleware.wrapStream = async ({ doStream }) => {
      const streamed = await doStream();
      const transform = new TransformStream<Record<string, unknown>, Record<string, unknown>>({
        transform(chunk, controller) {
          if (chunk.type !== 'tool-call') {
            controller.enqueue(chunk);
            return;
          }
          const decision = checkPart(chunk as ToolCallPart, guard);
          if (decision.action !== 'block') {
            controller.enqueue(chunk);
            return;
          }
          if (onBlock === 'throw') {
            controller.error(new ToolCallBlockedError(decision));
            return;
          }
          const id = `pp-refusal-${(chunk as ToolCallPart).toolCallId ?? 'call'}`;
          controller.enqueue({ type: 'text-start', id });
          controller.enqueue({ type: 'text-delta', id, delta: refusalText(decision) });
          controller.enqueue({ type: 'text-end', id });
        },
      });
      const stream = (streamed.stream as unknown as ReadableStream<Record<string, unknown>>).pipeThrough(transform);
      return { ...streamed, stream: stream as unknown as typeof streamed.stream };
    };
  }

  return middleware;
}
