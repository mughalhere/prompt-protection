import { normalize } from '../normalizer.js';
import { failedAnalysis } from '../core/analyze.js';
import { createProtectionSession } from '../session.js';
import type { ProtectionSession } from '../session.js';
import { buildShingles } from '../utils/shingle.js';
import type { AnalysisResult, AnalyzeOptions, FailMode, LoggingOptions } from '../types.js';
import { checkToolCall as runCheck } from './check.js';
import { DEFAULT_POLICIES } from './policy.js';
import { SourceIndex, identifierValues, stringifyValue } from './provenance.js';
import type { TrustState } from './provenance.js';
import { createSinkResolver } from './sinks.js';
import type {
  Guard,
  GuardDecision,
  GuardOptions,
  GuardSpotlightOptions,
  MemoryWriteOptions,
  MemoryWriteResult,
  TaintOptions,
  TaintedSource,
  ToolCall,
} from './types.js';
import { createToolApproval, wrapTools as wrapWithHooks } from './wrap.js';
import { spotlight, unspotlight } from '../spotlight/index.js';

const DEFAULT_MAX_SOURCES = 64;
const DEFAULT_MAX_SOURCE_CHARS = 200_000;
const DEFAULT_MIN_CONTAINMENT = 0.5;
const DEFAULT_MIN_CHAR_CONTAINMENT = 0.6;
const MAX_TRUST_TEXT = 50_000;

const LOGGING_KEYS: ReadonlyArray<keyof LoggingOptions> = [
  'logger', 'logLevels', 'includeContent', 'maxContentLength', 'onLoggerError',
];

function pickLogging(options: GuardOptions): LoggingOptions {
  const out: Record<string, unknown> = {};
  for (const key of LOGGING_KEYS) if (options[key] !== undefined) out[key] = options[key];
  return out as LoggingOptions;
}

function resolveSpotlight(option: GuardOptions['spotlight']): GuardSpotlightOptions | null {
  if (option === undefined) return null;
  return typeof option === 'string' ? { mode: option } : option;
}

/**
 * Creates a tool-call guard. Tool results enter through `taint`, user turns
 * through `trust` / `analyzeUserTurn`, and every model-proposed call goes
 * through `checkToolCall` before execution.
 */
export function createGuard(options: GuardOptions = {}): Guard {
  const analyzeOptions: AnalyzeOptions = { ...(options.analyzeOptions ?? {}) };
  const session: ProtectionSession = options.session ?? createProtectionSession(options.analyzeOptions ?? {});
  const logging = pickLogging(options);
  const resolveSink = createSinkResolver(options.sinks);
  const policies = options.policies ?? DEFAULT_POLICIES;
  const thresholds = {
    minContainment: options.minContainment ?? DEFAULT_MIN_CONTAINMENT,
    minCharContainment: options.minCharContainment ?? DEFAULT_MIN_CHAR_CONTAINMENT,
  };
  const maxSources = options.maxSources ?? DEFAULT_MAX_SOURCES;
  const maxSourceChars = options.maxSourceChars ?? DEFAULT_MAX_SOURCE_CHARS;
  const spot = resolveSpotlight(options.spotlight);
  const failMode: FailMode = options.failMode ?? 'closed';
  if (analyzeOptions.failMode === undefined) analyzeOptions.failMode = failMode;
  const marker = spot ? (spot.marker ?? spotlight('', { mode: spot.mode }).marker) : '';

  let index = new SourceIndex(maxSources, maxSourceChars);
  let trust: TrustState = { identifiers: new Set(options.trustedIdentifiers?.map((s) => s.toLowerCase())), text: '' };
  let plan: ReadonlySet<string> | null = null;
  let turn = 0;
  let seq = 0;

  function taint(source: string, value: unknown, taintOptions: TaintOptions = {}): TaintedSource {
    const id = taintOptions.id ?? `${source}#${++seq}`;
    const existing = index.get(id);
    if (existing !== undefined) return existing;

    const text = stringifyValue(value).slice(0, maxSourceChars);
    const { normalized } = normalize(text);
    // Session scoring on purpose: a blocked tool result feeds deferred-reference correlation.
    let result: AnalysisResult;
    try {
      result = session.analyze(text, { ...analyzeOptions, analyzeRoles: 'all' });
    } catch (err) {
      result = failedAnalysis(err, failMode, analyzeOptions.threshold ?? 35);
    }
    const entry: TaintedSource = {
      id,
      tool: source,
      text,
      normalized,
      shingles: buildShingles(normalized, 1),
      identifiers: identifierValues(text),
      injection: {
        score: result.score,
        action: result.action,
        categories: result.categories,
        ...(result.ml !== undefined ? { mlProbability: result.ml.probability } : {}),
      },
      turn,
      timestamp: Date.now(),
    };
    return index.add(entry);
  }

  function trustText(text: string): void {
    const { normalized } = normalize(text);
    for (const v of identifierValues(text).keys()) trust.identifiers.add(v);
    const joined = trust.text.length > 0 ? `${trust.text}\n${normalized}` : normalized;
    trust.text = joined.length > MAX_TRUST_TEXT ? joined.slice(joined.length - MAX_TRUST_TEXT) : joined;
  }

  function analyzeUserTurn(prompt: string, turnOptions: AnalyzeOptions = {}): AnalysisResult {
    trustText(prompt);
    return session.analyze(prompt, { ...analyzeOptions, ...turnOptions });
  }

  const unmark = spot ? (leaf: string) => unspotlight(leaf, marker, spot.mode) : undefined;

  const recent = new Map<string, GuardDecision>();
  const RECENT_MAX = 64;

  function remember(decision: GuardDecision): GuardDecision {
    if (decision.toolCallId !== undefined) {
      recent.delete(decision.toolCallId);
      recent.set(decision.toolCallId, decision);
      if (recent.size > RECENT_MAX) recent.delete(recent.keys().next().value as string);
    }
    return decision;
  }

  function check(call: ToolCall): GuardDecision {
    return remember(runCheck(call, {
      index,
      trust,
      thresholds,
      policies,
      resolveSink,
      plan,
      turn,
      analyzeOptions,
      logging,
      failMode,
      ...(unmark ? { unmark } : {}),
    }));
  }

  function taintMemoryWrite(source: string, value: unknown, memoryOptions: MemoryWriteOptions = {}): MemoryWriteResult {
    const entry = taint(source, value, memoryOptions.id !== undefined ? { id: memoryOptions.id } : {});
    const policy = memoryOptions.policy ?? 'reject-blocked';
    const action = entry.injection.action;
    const store = !(policy === 'reject-blocked' && action === 'block');
    const result: MemoryWriteResult = { source: entry, action, store };
    if (spot) result.spotlit = spotlight(entry.text, { mode: spot.mode, marker, sourceId: entry.id }).text;
    return result;
  }

  const guard: Guard = {
    taint,
    trust: trustText,
    analyzeUserTurn,
    checkToolCall: check,
    plan(allowedTools) {
      plan = allowedTools === null ? null : new Set(allowedTools);
    },
    wrapTools(tools) {
      return wrapWithHooks(tools, {
        check,
        taint: (tool, value, id) => {
          taint(tool, value, id !== undefined ? { id } : {});
        },
        ...(spot
          ? { mark: (text: string, sourceId: string) => spotlight(text, { mode: spot.mode, marker, sourceId }).text }
          : {}),
      });
    },
    vercelToolApproval: () => createToolApproval(check),
    taintMemoryWrite,
    lastDecision: (toolCallId) => recent.get(toolCallId),
    nextTurn() {
      turn += 1;
    },
    clear() {
      index = new SourceIndex(maxSources, maxSourceChars);
      trust = { identifiers: new Set(options.trustedIdentifiers?.map((s) => s.toLowerCase())), text: '' };
      plan = null;
      turn = 0;
      recent.clear();
      session.clear();
    },
    get session() {
      return session;
    },
    get sources() {
      return index.sources;
    },
    get turn() {
      return turn;
    },
  };
  return guard;
}
