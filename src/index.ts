// Stable tier: full semver, see docs/API_STABILITY.md. Engine plumbing is in
// `prompt-protection/internal`; the classifier, spotlighting, canaries and the guard
// live on their own subpaths (`/ml`, `/spotlight`, `/canary`, `/guard`).
export { analyzePrompt, verifyPrompt, stripPrompt, scanToolDefinition } from './api.js';
export { verifyPromptAsync } from './async.js';
export { analyzeOutput } from './output.js';
export { PromptInjectionError } from './error.js';
export { createProtectionSession } from './session.js';
export { createConsoleLogger } from './logging.js';
export { ClaudeAdapter } from './adapters/claude.js';
export { OpenAIAdapter } from './adapters/openai.js';
export { RULES_VERSION } from './patterns/version.js';

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
  Canary,
  CanaryDetection,
  CanaryVariant,
  PromptSimilarity,
  FailMode,
  AnalysisError,
  FlowSummary,
  RuleMappings,
  RuleOrigin,
} from './types.js';
export type { ProtectionSession, ProtectionSessionOptions } from './session.js';
