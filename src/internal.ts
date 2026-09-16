// Internal tier: engine plumbing with no compatibility contract; any release may
// change or remove it. Prefer the root entry or a documented subpath.
export { analyzePromptWith, computeSeverity, INTERNAL_ERROR_RULE } from './core/analyze.js';
export { normalize } from './normalizer.js';
export { resolveAction, precisionAllowsBlock } from './verdict.js';
export { flattenChatMessages, isChatMessageArray, resolvePromptInput } from './messages.js';
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
export type { NormalizeResult } from './normalizer.js';
export type { AnalyzeFn } from './core/analyze.js';
