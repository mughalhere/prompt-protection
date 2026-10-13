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
  approvalMismatch,
  approvalExpired,
  lineageUntrusted,
} from './policy.js';
export type { PolicyOutcome } from './policy.js';
export { DEFAULT_SINK_PATTERNS, defaultSink, createSinkResolver, EXFIL_SINKS, EXEC_SINKS } from './sinks.js';
export type { SinkPattern } from './sinks.js';
export {
  SourceIndex,
  collectLeaves,
  detectFlows,
  identifierValues,
  urlPathOf,
  stringifyValue,
  containmentOf,
  defang,
  keyOf,
  DESTINATION_KEYS,
  DESTINATION_KINDS,
  MIN_DESTINATION_CHARS,
  MIN_EXACT_CHARS,
  MIN_CONTENT_WORDS,
  MIN_CONTENT_CHARS,
  MIN_URL_PATH_CHARS,
} from './provenance.js';
export type { ArgLeaf, IndexedSource, FlowThresholds, TrustState, FlowReport } from './provenance.js';
export { wrapTools, toApprovalOutcome, createToolApproval } from './wrap.js';
export type { WrapHooks } from './wrap.js';
export { DECISION_REASONS, isDecisionReason } from './reasons.js';
export type { DecisionReason } from './reasons.js';
export { TRUST_LABEL_RANK, STRONG_EDGE, MIN_EDGE, rankOf, maxLabel, deriveLabel, isMemoryEntry } from './memory.js';
export type { TrustLabel, LineageKind, LineageEdge, MemoryEntry, MemoryReadResult } from './memory.js';
export { HandoffError, isTaintHandoff, assertTaintHandoff } from './handoff.js';
export type { TaintHandoff, HandoffSource } from './handoff.js';
export {
  ApprovalMismatchError,
  createApprovalStore,
  renderApprovalCard,
  DEFAULT_APPROVAL_TTL_MS,
  DEFAULT_APPROVAL_MAX,
} from './approval.js';
export type {
  ApprovalRecord,
  ApprovalStatus,
  ApprovalState,
  ApprovalField,
  ApprovalFieldKind,
  ApprovalCard,
  ApprovalOptions,
  ApprovalMismatchCode,
  ApprovalStore,
} from './approval.js';
export { canonicalJson, digest, digestSyncWeak, CanonicalJsonError } from '../utils/canonical.js';
export type { CanonicalJsonErrorCode } from '../utils/canonical.js';
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
  MemoryWriteOptions,
  MemoryWriteResult,
  ToolApprovalOutcome,
  ToolApprovalInput,
  WrappableTool,
  Guard,
} from './types.js';
export { pinTools, verifyTools, toolIdentity, toolIdentities, identityText, isToolLock, UNLOCKED } from './pin.js';
export type { ToolAnnotations, ToolLike, ToolSet, PinnedTool, ToolLock, ToolDrift, ToolIdentity, LockView } from './pin.js';
export { createBudget, DEFAULT_MAX_REPEAT_IDENTICAL } from './budgets.js';
export type { BudgetOptions, BudgetState, Budget } from './budgets.js';
export { toolUnpinned, toolDrift, budgetExceeded } from './policy.js';
export type { LockOptions, LockState } from './types.js';
export { explain } from './explain.js';
export type { ExplainStep, Explanation } from './explain.js';
export { resolvePreset, PRESETS, STRICT_POLICIES, PERMISSIVE_POLICIES } from './presets.js';
export type { GuardPreset } from './presets.js';
export { turnUntrustedToUntrustedDestination } from './policy.js';
export { envelopeInvalid, handoffUntrusted } from './policy.js';
export type { TaintEnvelopeOptions, TaintEnvelopeResult, AbsorbSealedResult } from './types.js';
