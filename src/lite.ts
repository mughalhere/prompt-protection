// Rules-only entry (`prompt-protection/lite`): no embedded model, 2.x footprint.
import { analyzePromptWith, stripPromptWith, verifyPromptWith } from './core/analyze.js';

export const analyzePrompt = analyzePromptWith(null);
export const verifyPrompt = verifyPromptWith(analyzePrompt);
export const stripPrompt = stripPromptWith(analyzePrompt);

export { analyzePromptWith, computeSeverity } from './core/analyze.js';
export { analyzeOutput } from './output.js';
export { normalize } from './normalizer.js';
export { PromptInjectionError } from './error.js';
export { resolveAction, precisionAllowsBlock } from './verdict.js';
export { ALL_RULES, OUTPUT_RULES, TOOL_RULES } from './patterns/index.js';

export type { NormalizeResult } from './normalizer.js';
export type { AnalyzeFn } from './core/analyze.js';
export type { Classifier, ClassifierMeta, ClassifierThresholds } from './ml/types.js';
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
export { spotlight, unspotlight, spotlightInstruction } from './spotlight/index.js';
export { createCanary, injectCanary, detectCanary, promptSimilarity } from './canary/index.js';
export type { SpotlightMode, SpotlightOptions, SpotlightResult } from './spotlight/index.js';
export type { CreateCanaryOptions, InjectCanaryOptions, DetectCanaryOptions } from './canary/index.js';
export type { Canary, CanaryDetection, CanaryVariant, PromptSimilarity } from './types.js';
