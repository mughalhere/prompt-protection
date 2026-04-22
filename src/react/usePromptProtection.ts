import { useState, useCallback } from 'react';
import { stripPrompt, analyzePrompt } from '../api.js';
import { PromptInjectionError } from '../error.js';
import type { AnalysisResult, VerifyOptions, StripOptions } from '../types.js';

export interface UsePromptProtectionOptions extends VerifyOptions {}

export interface UsePromptProtectionResult {
  /** Throws PromptInjectionError if the prompt is malicious */
  verify: (prompt: string, options?: VerifyOptions) => void;
  /** Returns a cleaned prompt with malicious spans removed */
  strip: (prompt: string, options?: StripOptions) => string;
  /** Returns the full analysis result without throwing */
  analyze: (prompt: string) => AnalysisResult;
  /** The last analysis result, or null if no prompt has been checked yet */
  result: AnalysisResult | null;
  /** The last error thrown by verify, or null if the last check passed */
  error: PromptInjectionError | null;
  /** Reset state */
  reset: () => void;
}

/**
 * React hook for client-side prompt protection.
 * Runs fully offline — zero network calls.
 *
 * @example
 * const { verify, error } = usePromptProtection({ threshold: 35 });
 *
 * const handleSubmit = () => {
 *   try {
 *     verify(userInput);
 *     sendToLLM(userInput);
 *   } catch (e) {
 *     // error state is automatically set
 *   }
 * };
 */
export function usePromptProtection(
  defaultOptions: UsePromptProtectionOptions = {},
): UsePromptProtectionResult {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<PromptInjectionError | null>(null);

  const verify = useCallback(
    (prompt: string, options?: VerifyOptions) => {
      const mergedOptions = { ...defaultOptions, ...options };
      const analysis = analyzePrompt(prompt, mergedOptions);
      setResult(analysis);

      if (analysis.isMalicious) {
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
    [defaultOptions],
  );

  const strip = useCallback(
    (prompt: string, options?: StripOptions) => {
      const mergedOptions = { ...defaultOptions, ...options };
      return stripPrompt(prompt, mergedOptions);
    },
    [defaultOptions],
  );

  const analyze = useCallback(
    (prompt: string) => {
      const analysis = analyzePrompt(prompt, defaultOptions);
      setResult(analysis);
      return analysis;
    },
    [defaultOptions],
  );

  const reset = useCallback(() => {
    setResult(null);
    setError(null);
  }, []);

  return { verify, strip, analyze, result, error, reset };
}
