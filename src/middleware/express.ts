import { verifyPrompt } from '../api.js';
import { PromptInjectionError } from '../error.js';
import type { VerifyOptions } from '../types.js';

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
}

/**
 * Express middleware that blocks requests containing malicious prompts.
 *
 * @example
 * app.use(express.json());
 * app.use(promptProtectionMiddleware({ field: 'prompt' }));
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
    if (typeof prompt !== 'string') {
      next();
      return;
    }

    try {
      verifyPrompt(prompt, options);
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
