export { analyzePrompt, verifyPrompt, stripPrompt } from './api.js';
export { verifyPromptAsync } from './async.js';
export { analyzeOutput } from './output.js';
export { PromptInjectionError } from './error.js';
export { ClaudeAdapter } from './adapters/claude.js';
export { OpenAIAdapter } from './adapters/openai.js';
export { flattenChatMessages, isChatMessageArray, resolvePromptInput } from './messages.js';
export { ALL_RULES, OUTPUT_RULES, injectionRules, jailbreakRules, exfiltrationRules, bypassRules, socialEngineeringRules, dataFishingRules, contextSmugglingRules, outputRules } from './patterns/index.js';

export type {
  ThreatCategory,
  SeverityLevel,
  PatternRule,
  PatternMatch,
  AnalysisResult,
  AnalyzeOptions,
  AnalyzeRoles,
  ChatMessage,
  PromptInput,
  VerifyOptions,
  StripOptions,
  AIAdapter,
  AsyncVerifyOptions,
  PromptInjectionErrorDetails,
  OutputAnalysisResult,
  OutputAnalysisOptions,
} from './types.js';
