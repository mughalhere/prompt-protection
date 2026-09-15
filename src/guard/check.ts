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
import { collectLeaves, detectFlows } from './provenance.js';
import type { FlowThresholds, SourceIndex, TrustState } from './provenance.js';
import { evaluatePolicies } from './policy.js';
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
  }, ctx.failMode);

  const action = toAction(outcome.action);
  const threshold = ctx.analyzeOptions.threshold ?? DEFAULT_THRESHOLD;
  const decision: GuardDecision = {
    action,
    requiresConfirmation: outcome.action === 'confirm',
    toolName: call.toolName,
    ...(call.toolCallId !== undefined ? { toolCallId: call.toolCallId } : {}),
    sink,
    flows,
    reasons: outcome.reasons,
    ...(outcome.policy !== undefined ? { policy: outcome.policy } : {}),
    argsAnalysis: withFlowMatches(rawArgs, flows, action, threshold),
  };

  emitToolCallLog({ ...decision, flows: summarizeFlows(flows) }, argsText, ctx.logging);
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
