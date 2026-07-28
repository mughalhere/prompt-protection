import { useState, useCallback, useMemo, useRef } from 'react';
import { stripPrompt, analyzePrompt } from '../api.js';
import { PromptInjectionError } from '../error.js';
import {
  createProtectionSession,
  type ProtectionSession,
} from '../session.js';
import type { AnalysisResult, PromptInput, VerifyOptions, StripOptions } from '../types.js';

export interface UsePromptProtectionOptions extends VerifyOptions {
  /**
   * When true, the hook owns a `ProtectionSession` so deferred follow-ups
   * (e.g. "process the last prompt") correlate with recently blocked turns.
   * Default: false (stateless per-call behaviour).
   */
  enableSession?: boolean;
  /** External session; takes precedence over `enableSession`. */
  session?: ProtectionSession;
}

export interface UsePromptProtectionResult {
  /** Throws PromptInjectionError if the prompt is blocked */
  verify: (prompt: PromptInput, options?: VerifyOptions) => void;
  /** Returns a cleaned prompt with malicious spans removed */
  strip: (prompt: PromptInput, options?: StripOptions) => string;
  /** Returns the full analysis result without throwing */
  analyze: (prompt: PromptInput) => AnalysisResult;
  /** The last analysis result, or null if no prompt has been checked yet */
  result: AnalysisResult | null;
  /** The last error thrown by verify, or null if the last check passed */
  error: PromptInjectionError | null;
  /** Reset analysis/error state (and clear session history when enabled) */
  reset: () => void;
}

/**
 * React hook for client-side prompt protection.
 * Runs fully offline — zero network calls.
 * Flagged prompts set `result.action` to `'flag'` but do not throw.
 *
 * @example
 * const { verify, error, result } = usePromptProtection({
 *   threshold: 35,
 *   flagThreshold: 25,
 *   enableSession: true,
 * });
 *
 * const handleSubmit = () => {
 *   try {
 *     verify(userInput);
 *     sendToLLM(userInput);
 *   } catch (e) {
 *     // error state is automatically set on block
 *   }
 * };
 */
export function usePromptProtection(
  defaultOptions: UsePromptProtectionOptions = {},
): UsePromptProtectionResult {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<PromptInjectionError | null>(null);

  const { enableSession = false, session: externalSession, ...analyzeDefaults } =
    defaultOptions;

  const ownedSessionRef = useRef<ProtectionSession | null>(null);
  if (enableSession && !externalSession && ownedSessionRef.current === null) {
    ownedSessionRef.current = createProtectionSession(analyzeDefaults);
  }

  const activeSession = useMemo(() => {
    if (externalSession) return externalSession;
    if (enableSession) return ownedSessionRef.current;
    return null;
  }, [externalSession, enableSession]);

  const verify = useCallback(
    (prompt: PromptInput, options?: VerifyOptions) => {
      const mergedOptions = { ...analyzeDefaults, ...options };
      const analysis = activeSession
        ? activeSession.analyze(prompt, mergedOptions)
        : analyzePrompt(prompt, mergedOptions);
      setResult(analysis);

      if (analysis.action === 'block') {
        const err = new PromptInjectionError({
          score: analysis.score,
          matches: analysis.matches,
          categories: analysis.categories,
        });
        setError(err);
        throw err;
      }

      setError(null);
    },
    [analyzeDefaults, activeSession],
  );

  const strip = useCallback(
    (prompt: PromptInput, options?: StripOptions) => {
      const mergedOptions = { ...analyzeDefaults, ...options };
      if (activeSession) {
        return activeSession.strip(prompt, mergedOptions);
      }
      return stripPrompt(prompt, mergedOptions);
    },
    [analyzeDefaults, activeSession],
  );

  const analyze = useCallback(
    (prompt: PromptInput) => {
      const analysis = activeSession
        ? activeSession.analyze(prompt, analyzeDefaults)
        : analyzePrompt(prompt, analyzeDefaults);
      setResult(analysis);
      return analysis;
    },
    [analyzeDefaults, activeSession],
  );

  const reset = useCallback(() => {
    setResult(null);
    setError(null);
    activeSession?.clear();
  }, [activeSession]);

  return { verify, strip, analyze, result, error, reset };
}
