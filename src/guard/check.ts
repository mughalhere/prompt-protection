import { analyzePrompt } from '../api.js';
import { computeSeverity, failedAnalysis } from '../core/analyze.js';
import { emitToolCallLog } from '../logging.js';
import type {
  Action,
  AnalysisResult,
  AnalyzeOptions,
  FailMode,
  FlowSummary,
  LoggingOptions,
  PatternMatch,
  PatternRule,
  ThreatCategory,
} from '../types.js';
import { canonicalJson } from '../utils/canonical.js';
import { collectLeaves, detectFlows } from './provenance.js';
import type { FlowThresholds, SourceIndex, TrustState } from './provenance.js';
import { evaluatePolicies } from './policy.js';
import type { ApprovalStore } from './approval.js';
import type { Budget } from './budgets.js';
import { UNLOCKED } from './pin.js';
import type { LockView } from './pin.js';
import type { TrustLabel } from './memory.js';
import type { DecisionReason } from './reasons.js';
import type { Flow, GuardDecision, GuardPolicy, PolicyAction, SinkKind, ToolCall } from './types.js';

const FLOW_RULE: PatternRule = {
  id: 'guard-data-flow',
  category: 'data-flow',
  pattern: /(?!)/, // never matches text; synthetic matches only
  weight: 10,
  precision: 'high',
  description: 'Untrusted tool-result data reached a tool-call argument',
};

const DEFAULT_THRESHOLD = 35;

export interface CheckContext {
  index: SourceIndex;
  trust: TrustState;
  thresholds: FlowThresholds;
  policies: readonly GuardPolicy[];
  resolveSink: (toolName: string) => SinkKind;
  plan: ReadonlySet<string> | null;
  turn: number;
  analyzeOptions: AnalyzeOptions;
  logging: LoggingOptions;
  failMode: FailMode;
  /** Applied to each leaf before flow detection (spotlight removal). */
  unmark?: (leaf: string) => string;
  /** Provenance label of a source id. */
  labelOf: (sourceId: string) => TrustLabel;
  /** Sub-agent depth of the guard. */
  depth: number;
  /** Approval store; `lookup` runs before policies, `consume` after an approved call passes. */
  approvals?: Pick<ApprovalStore, 'lookup' | 'consume'>;
  /** Lock view per tool name; `UNLOCKED` when no lock is installed. */
  lockOf?: (toolName: string) => LockView;
  /** Counts the attempt before policies run; absent when budgets are off. */
  budget?: Pick<Budget, 'record'>;
  requireLock?: boolean;
  /** `observe`: compute the verdict, record it, return `allow`. Default `enforce`. */
  mode?: 'enforce' | 'observe';
}

function summarizeFlows(flows: Flow[]): FlowSummary[] {
  return flows.map((f) => ({ kind: f.kind, sourceId: f.sourceId, sourceTool: f.sourceTool, path: f.path, strength: f.strength }));
}

/** Decision + log when the guard itself throws; block unless `failMode` is `'open'`. */
function failedDecision(err: unknown, call: ToolCall, ctx: CheckContext): GuardDecision {
  const threshold = ctx.analyzeOptions.threshold ?? DEFAULT_THRESHOLD;
  const argsAnalysis = failedAnalysis(err, ctx.failMode, threshold);
  let sink: SinkKind = 'none';
  try {
    sink = ctx.resolveSink(call.toolName);
  } catch {
    /* resolver is one of the things that may have thrown */
  }
  const decision: GuardDecision = {
    action: argsAnalysis.action,
    requiresConfirmation: false,
    toolName: call.toolName,
    ...(call.toolCallId !== undefined ? { toolCallId: call.toolCallId } : {}),
    sink,
    flows: [],
    reasons: ['internal-error'],
    policy: 'internal-error',
    argsAnalysis,
    depth: ctx.depth,
  };
  emitToolCallLog({ ...decision, flows: [] }, '', ctx.logging);
  return decision;
}

/** Pure decision function; state is passed in so `createGuard` stays thin. */
export function checkToolCall(call: ToolCall, ctx: CheckContext): GuardDecision {
  try {
    return runCheck(call, ctx);
  } catch (err) {
    return failedDecision(err, call, ctx);
  }
}

function toAction(action: PolicyAction): Action {
  return action === 'confirm' ? 'flag' : action;
}

function withFlowMatches(result: AnalysisResult, flows: Flow[], action: Action, threshold: number): AnalysisResult {
  if (flows.length === 0 && action === result.action) return result;
  const synthetic: PatternMatch[] = flows.map((f) => ({
    rule: { ...FLOW_RULE, id: `guard-data-flow-${f.kind}` },
    matchedText: f.value,
    startIndex: 0,
    endIndex: 0,
  }));
  const categories = flows.length > 0
    ? [...new Set<ThreatCategory>([...result.categories, 'data-flow'])]
    : result.categories;
  const score = action === 'block' ? Math.max(result.score, threshold) : result.score;
  return {
    ...result,
    score,
    severity: computeSeverity(score),
    action,
    isMalicious: action === 'block',
    matches: [...result.matches, ...synthetic],
    categories,
  };
}

function runCheck(call: ToolCall, ctx: CheckContext): GuardDecision {
  const leaves = collectLeaves(call.args).map((leaf) =>
    ctx.unmark ? { ...leaf, value: ctx.unmark(leaf.value) } : leaf,
  );
  const sink = ctx.resolveSink(call.toolName);
  const { flows, untrustedLeaves, destinationTrusted } = detectFlows(leaves, ctx.index, ctx.trust, ctx.thresholds);
  const argsText = untrustedLeaves.map((l) => l.value).join('\n');
  const rawArgs = argsText.length > 0 ? analyzePrompt(argsText, ctx.analyzeOptions) : emptyAnalysis();

  const sources = ctx.index.sources;
  const turnSources = sources.filter((s) => s.turn === ctx.turn);
  // Sync string compare against the confirmed card; hashing never runs on the check path.
  const approval = ctx.approvals ? ctx.approvals.lookup(call, canonicalJson(call.args)) : null;
  const lock = ctx.lockOf ? ctx.lockOf(call.toolName) : UNLOCKED;
  // Budgets count every attempt, blocked ones included: a loop of blocked calls is still a loop.
  const budget = ctx.budget ? ctx.budget.record(call, ctx.depth) : null;
  const outcome = evaluatePolicies(ctx.policies, {
    call,
    sink,
    flows,
    sources,
    turnSources,
    argsAnalysis: rawArgs,
    plan: ctx.plan,
    destinationTrusted,
    sourceById: (id) => ctx.index.get(id),
    labelOf: ctx.labelOf,
    depth: ctx.depth,
    approval,
    lock,
    budget,
    requireLock: ctx.requireLock ?? false,
  }, ctx.failMode);

  let policyAction: PolicyAction = outcome.action;
  let reasons: DecisionReason[] = outcome.reasons;
  // An approved, canonical-equal call clears a confirm. A block stays a block.
  if (approval?.status === 'approved' && policyAction === 'confirm') {
    policyAction = 'allow';
    reasons = ['approved', ...reasons];
    ctx.approvals?.consume(approval.id);
  }

  const enforced = toAction(policyAction);
  const observe = ctx.mode === 'observe';
  // Observe: the verdict is computed and recorded, never applied.
  const action: Action = observe ? 'allow' : enforced;
  const threshold = ctx.analyzeOptions.threshold ?? DEFAULT_THRESHOLD;
  const decision: GuardDecision = {
    action,
    requiresConfirmation: observe ? false : policyAction === 'confirm',
    toolName: call.toolName,
    ...(call.toolCallId !== undefined ? { toolCallId: call.toolCallId } : {}),
    sink,
    flows,
    reasons,
    ...(outcome.policy !== undefined && policyAction !== 'allow' ? { policy: outcome.policy } : {}),
    argsAnalysis: withFlowMatches(rawArgs, flows, enforced, threshold),
    depth: ctx.depth,
    ...(approval !== null ? { approval } : {}),
    ...(lock.locked ? { lock } : {}),
    ...(budget !== null ? { budget: { ...budget, toolCalls: { ...budget.toolCalls }, repeats: { ...budget.repeats }, exceeded: [...budget.exceeded] } } : {}),
    ...(observe ? { observedAction: enforced, observedRequiresConfirmation: policyAction === 'confirm' } : {}),
  };

  // The event carries the verdict that would have applied, so observe-mode blocks still reach the log.
  emitToolCallLog(
    { ...decision, flows: summarizeFlows(flows), ...(observe ? { action: enforced, mode: 'observe', observedAction: enforced } : {}) },
    argsText,
    ctx.logging,
  );
  return decision;
}

function emptyAnalysis(): AnalysisResult {
  return {
    score: 0,
    severity: 'safe',
    isMalicious: false,
    action: 'allow',
    matches: [],
    categories: [],
    normalizedPrompt: '',
  };
}
