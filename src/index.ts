export { analyzePrompt, verifyPrompt, stripPrompt, scanToolDefinition, computeSeverity } from './api.js';
export { analyzePromptWith } from './core/analyze.js';
export { mlClassifier, createClassifier, predict, fuseVerdict, ML_RULE_ID } from './ml/index.js';
export { normalize } from './normalizer.js';
export { verifyPromptAsync } from './async.js';
export { analyzeOutput } from './output.js';
export { PromptInjectionError } from './error.js';
export { ClaudeAdapter } from './adapters/claude.js';
export { OpenAIAdapter } from './adapters/openai.js';
export { flattenChatMessages, isChatMessageArray, resolvePromptInput } from './messages.js';
export { createConsoleLogger } from './logging.js';
export { resolveAction, precisionAllowsBlock } from './verdict.js';
export { createProtectionSession } from './session.js';
export {
  ALL_RULES,
  OUTPUT_RULES,
  TOOL_RULES,
  injectionRules,
  jailbreakRules,
  exfiltrationRules,
  bypassRules,
  socialEngineeringRules,
  dataFishingRules,
  contextSmugglingRules,
  toolPoisoningRules,
  outputRules,
  DEFERRED_REFERENCE_RULE_IDS,
} from './patterns/index.js';

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
  MlContribution,
  MlMode,
  ChatMessage,
  ToolDefinition,
  PromptInput,
  VerifyOptions,
  StripOptions,
  AIAdapter,
  AsyncVerifyOptions,
  PromptInjectionErrorDetails,
  OutputAnalysisResult,
  OutputAnalysisOptions,
  ProtectionEvent,
  ProtectionLogger,
  LoggingOptions,
  LogLevel,
} from './types.js';

export type { ProtectionSession, ProtectionSessionOptions } from './session.js';
export type { NormalizeResult } from './normalizer.js';
export type { AnalyzeFn } from './core/analyze.js';
export type { Classifier, ClassifierMeta, ClassifierThresholds, ModelMeta } from './ml/types.js';

// Spotlighting + canaries (v3)
export { spotlight, unspotlight, spotlightInstruction } from './spotlight/index.js';
export { createCanary, injectCanary, detectCanary, promptSimilarity } from './canary/index.js';
export type { SpotlightMode, SpotlightOptions, SpotlightResult } from './spotlight/index.js';
export type { CreateCanaryOptions, InjectCanaryOptions, DetectCanaryOptions } from './canary/index.js';
export type { Canary, CanaryDetection, CanaryVariant, PromptSimilarity } from './types.js';

// v3.1: fail-closed, rule-pack pinning, framework mappings (ATR loader lives in `prompt-protection/atr`)
export { RULES_VERSION } from './patterns/version.js';
export { RULE_MAPPINGS, withMappings } from './patterns/mappings.js';
export { INTERNAL_ERROR_RULE } from './core/analyze.js';
export type { FailMode, AnalysisError, FlowSummary, RuleMappings, RuleOrigin } from './types.js';
