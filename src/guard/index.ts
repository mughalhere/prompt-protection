export { createGuard } from './guard.js';
export { ToolCallBlockedError } from './errors.js';
export { checkToolCall } from './check.js';
export type { CheckContext } from './check.js';
export {
  DEFAULT_POLICIES,
  evaluatePolicies,
  planViolation,
  injectionSourceFlow,
  untrustedToExfilSink,
  untrustedToExec,
  untrustedToPayment,
  paymentConfirm,
  injectionThenSink,
  argsInjection,
} from './policy.js';
export type { PolicyOutcome } from './policy.js';
export { DEFAULT_SINK_PATTERNS, defaultSink, createSinkResolver, EXFIL_SINKS, EXEC_SINKS } from './sinks.js';
export type { SinkPattern } from './sinks.js';
export {
  SourceIndex,
  collectLeaves,
  detectFlows,
  identifierValues,
  stringifyValue,
  containmentOf,
  defang,
  DESTINATION_KEYS,
  DESTINATION_KINDS,
  MIN_DESTINATION_CHARS,
  MIN_EXACT_CHARS,
  MIN_CONTENT_WORDS,
  MIN_CONTENT_CHARS,
} from './provenance.js';
export type { ArgLeaf, IndexedSource, FlowThresholds, TrustState, FlowReport } from './provenance.js';
export { wrapTools, toApprovalOutcome, createToolApproval } from './wrap.js';
export type { WrapHooks } from './wrap.js';
export type {
  SinkKind,
  FlowKind,
  Flow,
  SourceInjection,
  TaintedSource,
  ToolCall,
  GuardDecision,
  PolicyAction,
  PolicyContext,
  GuardPolicy,
  SinkResolver,
  SpotlightMode,
  GuardSpotlightOptions,
  GuardOptions,
  TaintOptions,
  ToolApprovalOutcome,
  ToolApprovalInput,
  WrappableTool,
  Guard,
} from './types.js';
