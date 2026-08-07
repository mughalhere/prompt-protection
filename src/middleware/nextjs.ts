import { analyzePrompt } from '../api.js';
import { PromptInjectionError } from '../error.js';
import { isChatMessageArray } from '../messages.js';
import type { ProtectionSession } from '../session.js';
import type { AnalysisResult, PromptInput, VerifyOptions } from '../types.js';

interface NextRequest {
  json(): Promise<unknown>;
}

interface NextResponse {
  readonly ok: boolean;
}

interface NextResponseConstructor {
  json(body: unknown, init?: { status?: number }): NextResponse;
}

type RouteHandler = (req: NextRequest) => Promise<NextResponse> | NextResponse;

export interface NextjsProtectionOptions extends VerifyOptions {
  /** The JSON body field to check. Default: 'prompt' */
  field?: string;
  /** Custom error response factory */
  onError?: (err: PromptInjectionError) => NextResponse;
  /**
   * Called when the prompt is flagged but not blocked. Handler still runs after this.
   */
  onFlag?: (result: AnalysisResult) => void;
  /**
   * Shared protection session for multi-turn correlation.
   * Prefer `getSession` when sessions are keyed per user/conversation.
   */
  session?: ProtectionSession;
  /** Resolve a session per request (e.g. by conversation id). */
  getSession?: (req: NextRequest) => ProtectionSession | undefined;
}

function toAnalyzeOptions(options: NextjsProtectionOptions): VerifyOptions {
  const analyzeOpts: VerifyOptions = { ...options };
  delete (analyzeOpts as NextjsProtectionOptions).field;
  delete (analyzeOpts as NextjsProtectionOptions).onError;
  delete (analyzeOpts as NextjsProtectionOptions).onFlag;
  delete (analyzeOpts as NextjsProtectionOptions).session;
  delete (analyzeOpts as NextjsProtectionOptions).getSession;
  return analyzeOpts;
}

/**
 * Wraps a Next.js App Router route handler with prompt protection.
 * Reads the JSON body, checks the specified field, and returns 400 if blocked.
 * Flagged prompts continue (optional `onFlag` callback).
 *
 * @example
 * // app/api/chat/route.ts
 * export const POST = withPromptProtection(async (req) => {
 *   const { prompt } = await req.json();
 *   // ... call your LLM
 * }, { field: 'prompt', flagThreshold: 25 });
 */
export function withPromptProtection(
  handler: RouteHandler,
  options: NextjsProtectionOptions = {},
): RouteHandler {
  const field = options.field ?? 'prompt';

  return async (req: NextRequest) => {
    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return handler(req);
    }

    if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
      const bodyObj = body as Record<string, unknown>;
      const prompt = bodyObj[field];

      if (typeof prompt === 'string' || isChatMessageArray(prompt)) {
        const session = options.getSession?.(req) ?? options.session;
        const analyzeOpts = toAnalyzeOptions(options);

        const analysis = session
          ? session.analyze(prompt as PromptInput, analyzeOpts)
          : analyzePrompt(prompt as PromptInput, analyzeOpts);

        if (analysis.action === 'block') {
          const err = new PromptInjectionError({
            score: analysis.score,
            matches: analysis.matches,
            categories: analysis.categories,
          });

          if (options.onError) {
            return options.onError(err);
          }

          // Lazy import NextResponse so this module works without next installed
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          const nextServerModule = await import(
            /* webpackIgnore: true */ 'next/server' as string
          ).catch(() => null);
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          const NextResponse: NextResponseConstructor = (nextServerModule as { NextResponse?: NextResponseConstructor } | null)?.NextResponse ?? makeFallbackNextResponse();

          return NextResponse.json(
            {
              error: 'Malicious prompt detected',
              message: err.message,
              score: err.score,
              categories: err.categories,
            },
            { status: 400 },
          );
        }

        if (analysis.action === 'flag' && options.onFlag) {
          options.onFlag(analysis);
        }
      }
    }

    return handler(req);
  };
}

function makeFallbackNextResponse(): NextResponseConstructor {
  return {
    json(body: unknown, init?: { status?: number }): NextResponse {
      const status = init?.status ?? 200;
      const headers = new Headers({ 'Content-Type': 'application/json' });
      return new Response(JSON.stringify(body), { status, headers }) as unknown as NextResponse;
    },
  };
}
