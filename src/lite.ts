/**
 * @packageDocumentation
 * @beta Preview tier: may change in a minor release. See docs/API_STABILITY.md.
 */
// Rules-only entry (`prompt-protection/lite`): no embedded model, 2.x footprint.
import { analyzePromptWith, stripPromptWith, verifyPromptWith } from './core/analyze.js';

export const analyzePrompt = analyzePromptWith(null);
export const verifyPrompt = verifyPromptWith(analyzePrompt);
export const stripPrompt = stripPromptWith(analyzePrompt);

export { analyzeOutput } from './output.js';
export { RULES_VERSION } from './patterns/version.js';
export { PromptInjectionError } from './error.js';

export type {
  ThreatCategory,
  SeverityLevel,
  Action,
  RulePrecision,
  PatternRule,
  PatternMatch,
  AnalysisResult,
  AnalyzeOptions,
  AnalyzeRoles,
  ChatMessage,
  PromptInput,
  VerifyOptions,
  StripOptions,
  PromptInjectionErrorDetails,
  OutputAnalysisResult,
  OutputAnalysisOptions,
  ProtectionEvent,
  ProtectionLogger,
  LoggingOptions,
  LogLevel,
} from './types.js';

// Spotlighting + canaries are rules-only-safe, so the lite entry carries them too.
export type { Canary, CanaryDetection, CanaryVariant, PromptSimilarity } from './types.js';
