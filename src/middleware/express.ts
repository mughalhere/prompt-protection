import { analyzePrompt } from '../api.js';
import { PromptInjectionError } from '../error.js';
import { isChatMessageArray } from '../messages.js';
import type { AnalysisResult, PromptInput, VerifyOptions } from '../types.js';

type AnyObject = Record<string, unknown>;

interface ExpressRequest {
  body?: AnyObject;
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
}

type NextFunction = (err?: unknown) => void;

type ExpressMiddleware = (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void;

export interface PromptProtectionMiddlewareOptions extends VerifyOptions {
  /** The field in req.body to check. Default: 'prompt' */
  field?: string;
  /** Custom error handler. Default: 400 JSON response */
  onError?: (err: PromptInjectionError, req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void;
  /**
   * Called when the prompt is flagged but not blocked. Request continues after this.
   */
  onFlag?: (result: AnalysisResult, req: ExpressRequest, res: ExpressResponse) => void;
}

/**
 * Express middleware that blocks requests containing malicious prompts.
 * Flagged prompts continue (optional `onFlag` callback).
 *
 * @example
 * app.use(express.json());
 * app.use(promptProtectionMiddleware({ field: 'prompt', flagThreshold: 25 }));
 */
export function promptProtectionMiddleware(
  options: PromptProtectionMiddlewareOptions = {},
): ExpressMiddleware {
  const field = options.field ?? 'prompt';

  const defaultErrorHandler = (
    err: PromptInjectionError,
    _req: ExpressRequest,
    res: ExpressResponse,
    _next: NextFunction,
  ) => {
    res.status(400).json({
      error: 'Malicious prompt detected',
      message: err.message,
      score: err.score,
      categories: err.categories,
    });
  };

  const onError = options.onError ?? defaultErrorHandler;

  return (req, res, next) => {
    const body = req.body;
    if (!body || typeof body !== 'object') {
      next();
      return;
    }

    const prompt = body[field];
    const isValidPrompt =
      typeof prompt === 'string' || isChatMessageArray(prompt);
    if (!isValidPrompt) {
      next();
      return;
    }

    try {
      const analysis = analyzePrompt(prompt as PromptInput, options);

      if (analysis.action === 'block') {
        throw new PromptInjectionError({
          score: analysis.score,
          matches: analysis.matches,
          categories: analysis.categories,
        });
      }

      if (analysis.action === 'flag' && options.onFlag) {
        options.onFlag(analysis, req, res);
      }

      next();
    } catch (err) {
      if (err instanceof PromptInjectionError) {
        onError(err, req, res, next);
      } else {
        next(err);
      }
    }
  };
}
