import { verifyPrompt } from '../api.js';
import { PromptInjectionError } from '../error.js';
import type { VerifyOptions } from '../types.js';

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
}

/**
 * Wraps a Next.js App Router route handler with prompt protection.
 * Reads the JSON body, checks the specified field, and returns 400 if malicious.
 *
 * @example
 * // app/api/chat/route.ts
 * export const POST = withPromptProtection(async (req) => {
 *   const { prompt } = await req.json();
 *   // ... call your LLM
 * }, { field: 'prompt' });
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
      // If body parsing fails, let the handler deal with it
      return handler(req);
    }

    if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
      const bodyObj = body as Record<string, unknown>;
      const prompt = bodyObj[field];

      if (typeof prompt === 'string') {
        try {
          verifyPrompt(prompt, options);
        } catch (err) {
          if (err instanceof PromptInjectionError) {
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
          throw err;
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
      // Return a Response-compatible object
      return new Response(JSON.stringify(body), { status, headers }) as unknown as NextResponse;
    },
  };
}
