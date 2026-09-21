import { normalize } from '../normalizer.js';
import { failedAnalysis } from '../core/analyze.js';
import { createProtectionSession } from '../session.js';
import type { ProtectionSession } from '../session.js';
import { buildShingles } from '../utils/shingle.js';
import type { AnalysisResult, AnalyzeOptions, FailMode, LoggingOptions } from '../types.js';
import { canonicalJson, digest } from '../utils/canonical.js';
import { randomHex } from '../utils/random.js';
import { RULES_VERSION } from '../patterns/version.js';
import { checkToolCall as runCheck } from './check.js';
import { DEFAULT_POLICIES } from './policy.js';
import { SourceIndex, containmentOf, identifierValues, stringifyValue } from './provenance.js';
import type { TrustState } from './provenance.js';
import { createSinkResolver } from './sinks.js';
import { createApprovalStore, renderApprovalCard } from './approval.js';
import type { ApprovalCard } from './approval.js';
import { assertTaintHandoff } from './handoff.js';
import type { TaintHandoff } from './handoff.js';
import { deriveLabel, isMemoryEntry, maxLabel, MIN_EDGE } from './memory.js';
import type { LineageEdge, MemoryEntry, MemoryReadResult, TrustLabel } from './memory.js';
import type {
  Guard,
  GuardDecision,
  GuardOptions,
  GuardSpotlightOptions,
  LockOptions,
  SinkKind,
  MemoryWriteOptions,
  MemoryWriteResult,
  SourceInjection,
  TaintOptions,
  TaintedSource,
  TaintEnvelopeOptions,
  TaintEnvelopeResult,
  AbsorbSealedResult,
  ToolCall,
} from './types.js';
import { createToolApproval, wrapTools as wrapWithHooks } from './wrap.js';
import { isSpotlightBoundary, spotlight, unspotlight } from '../spotlight/index.js';
import { createBudget } from './budgets.js';
import type { BudgetState } from './budgets.js';
import { resolvePreset } from './presets.js';
import { EnvelopeError, open, seal } from '../envelope/index.js';
import type { Envelope, EnvelopeErrorCode, EnvelopeKey, OpenOptions } from '../envelope/index.js';
import { identityText, isToolLock, pinTools, toolIdentities, UNLOCKED, verifyTools } from './pin.js';
import type { LockView, ToolDrift, ToolLock, ToolSet } from './pin.js';
import { defaultSink } from './sinks.js';

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
  if (typeof option === 'string') return { mode: option };
  // A boundary carries its own marker; the guard marks and unmarks with it.
  if (isSpotlightBoundary(option)) return { mode: option.mode, marker: option.marker };
  return option;
}

/**
 * Creates a tool-call guard. Tool results enter through `taint`, user turns
 * through `trust` / `analyzeUserTurn`, and every model-proposed call goes
 * through `checkToolCall` before execution.
 */
export function createGuard(rawOptions: GuardOptions = {}): Guard {
  // A preset supplies defaults under the explicit options; `balanced` or none leaves them untouched.
  const options = resolvePreset(rawOptions);
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
  let depth = 0;
  const approvals = createApprovalStore(options.approvals);
  const maxMemoryEntries = options.memory?.maxEntries ?? maxSources;
  const requireLock = options.requireLock ?? false;
  const annotationsDefault = options.annotationsDefault ?? 'destructive';
  const budget = options.budgets !== undefined ? createBudget(options.budgets) : null;
  const explicitSink = typeof options.sinks === 'function' ? options.sinks : (name: string) =>
    options.sinks !== undefined && Object.prototype.hasOwnProperty.call(options.sinks, name)
      ? (options.sinks as Record<string, SinkKind>)[name]
      : undefined;

  let lock: ToolLock | null = null;
  let driftAction: 'block' | 'confirm' = 'block';
  /** Canonical identity text per tool at `pin` time, for sync drift checks in `wrapTools`. */
  let identities = new Map<string, string>();
  let drift = new Map<string, ToolDrift>();

  function lockOf(toolName: string): LockView {
    if (lock === null) return UNLOCKED;
    const pinned = lock.tools[toolName];
    return {
      locked: true,
      listed: pinned !== undefined,
      drift: drift.get(toolName) ?? null,
      annotations: pinned?.annotations ?? null,
      driftAction,
    };
  }

  /** Under a lock only: explicit map > `readOnlyHint` > heuristic; unannotated heuristic `none` → `unknown`. */
  function resolveSinkLocked(toolName: string): SinkKind {
    const explicit = explicitSink(toolName);
    if (explicit !== undefined) return explicit;
    if (lock === null) return resolveSink(toolName);
    const annotations = lock.tools[toolName]?.annotations;
    if (annotations?.readOnlyHint === true) return 'none';
    const heuristic = defaultSink(toolName);
    if (heuristic === 'none' && annotations === undefined && annotationsDefault === 'destructive') return 'unknown';
    return heuristic;
  }

  function installLock(next: ToolLock, lockOptions: LockOptions): void {
    lock = next;
    driftAction = lockOptions.drift ?? 'block';
    drift = new Map();
  }

  function syncDrift(tools: ToolSet): void {
    if (lock === null || identities.size === 0) return;
    const next = new Map<string, ToolDrift>();
    for (const [name, identity] of toolIdentities(tools)) {
      const expected = identities.get(name);
      const actual = identityText(identity);
      if (expected === undefined) next.set(name, { name, kind: 'unlisted' });
      else if (expected !== actual) next.set(name, { name, kind: 'changed' });
    }
    drift = next;
  }

  function ownLabel(injection: SourceInjection): TrustLabel {
    return injection.action === 'block' ? 'blocked' : 'tool';
  }

  function labelOf(sourceId: string): TrustLabel {
    const src = index.get(sourceId);
    if (src === undefined) return 'untrusted';
    return src.label ?? ownLabel(src.injection);
  }

  interface Provenance {
    label?: TrustLabel;
    lineage?: LineageEdge[];
    /** The label is signed by a verified producer: accept it as-is, unless the text itself scores as injection. */
    attested?: boolean;
  }

  function taint(source: string, value: unknown, taintOptions: TaintOptions = {}, provenance: Provenance = {}): TaintedSource {
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
    const injection: SourceInjection = {
      score: result.score,
      action: result.action,
      categories: result.categories,
      ...(result.ml !== undefined ? { mlProbability: result.ml.probability } : {}),
    };
    // A stored or inherited label only ever raises the source's own; an attested (signed) label is
    // taken as given, except that injection-scored text is blocked whatever the producer claims.
    const own = ownLabel(injection);
    const label =
      provenance.label === undefined ? undefined : provenance.attested === true && own !== 'blocked' ? provenance.label : maxLabel(own, provenance.label);
    const entry: TaintedSource = {
      id,
      tool: source,
      text,
      normalized,
      shingles: buildShingles(normalized, 1),
      identifiers: identifierValues(text),
      injection,
      turn,
      timestamp: Date.now(),
      ...(label !== undefined ? { label } : {}),
      ...(provenance.lineage !== undefined ? { lineage: provenance.lineage } : {}),
    };
    return index.add(entry);
  }

  /** Containment of `text` in each live source other than `selfId`, as `derive` edges. */
  function autoEdges(text: string, selfId: string): LineageEdge[] {
    const edges: LineageEdge[] = [];
    for (const src of index.sources) {
      if (src.id === selfId) continue;
      const c = containmentOf(text, src.normalized);
      const strength = Math.max(c.word, c.char);
      if (strength >= MIN_EDGE) edges.push({ from: src.id, kind: 'derive', strength });
    }
    return edges;
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
      resolveSink: resolveSinkLocked,
      plan,
      turn,
      analyzeOptions,
      logging,
      failMode,
      labelOf,
      depth,
      approvals,
      lockOf,
      requireLock,
      ...(budget !== null ? { budget } : {}),
      ...(options.mode !== undefined ? { mode: options.mode } : {}),
      ...(unmark ? { unmark } : {}),
    }));
  }

  function taintMemoryWrite(source: string, value: unknown, memoryOptions: MemoryWriteOptions = {}): MemoryWriteResult {
    const src = taint(source, value, memoryOptions.id !== undefined ? { id: memoryOptions.id } : {});
    const explicit: LineageEdge[] = (memoryOptions.derivedFrom ?? []).map((from) => ({ from, kind: 'copy', strength: 1 }));
    const lineage = explicit.length > 0 ? explicit : autoEdges(src.text, src.id);
    const derived = deriveLabel(lineage, labelOf, ownLabel(src.injection));
    const label = memoryOptions.label !== undefined ? maxLabel(derived, memoryOptions.label) : derived;
    src.label = label;
    src.lineage = lineage;
    const entry: MemoryEntry = {
      v: 1,
      id: src.id,
      ...(memoryOptions.key !== undefined ? { key: memoryOptions.key } : {}),
      value: src.text,
      label,
      sourceIds: lineage.filter((e) => e.strength >= 0.5).map((e) => e.from),
      lineage,
      injection: src.injection,
      rulesVersion: RULES_VERSION,
      turn,
      ts: new Date(src.timestamp).toISOString(),
    };
    const policy = memoryOptions.policy ?? 'reject-blocked';
    const action = src.injection.action;
    const store = !(policy === 'reject-blocked' && (action === 'block' || label === 'blocked'));
    const result: MemoryWriteResult = { source: src, action, store, entry };
    if (spot) result.spotlit = spotlight(src.text, { mode: spot.mode, marker, sourceId: src.id }).text;
    return result;
  }

  function memoryRead(entries: readonly MemoryEntry[]): MemoryReadResult {
    const sources: TaintedSource[] = [];
    const edges: LineageEdge[] = [];
    let label: TrustLabel = 'tool';
    let worst: SourceInjection = { score: 0, action: 'allow', categories: [] };
    for (const entry of entries.slice(0, maxMemoryEntries)) {
      if (!isMemoryEntry(entry)) throw new TypeError('memoryRead: not a v1 MemoryEntry');
      const read: LineageEdge = { from: entry.id, kind: 'read', strength: 1 };
      const lineage = [...entry.lineage, read];
      // Re-scored under the current rules; the stored label can only raise the result.
      const src = taint(`memory:${entry.key ?? entry.id}`, entry.value, { id: `mem:${entry.id}` }, { label: entry.label, lineage });
      sources.push(src);
      edges.push(...lineage);
      label = maxLabel(label, src.label ?? ownLabel(src.injection));
      if (src.injection.score > worst.score) worst = src.injection;
    }
    return { sources, label, edges, injection: worst };
  }

  function derive(value: unknown, fromSourceIds: readonly string[], taintOptions: TaintOptions = {}): TaintedSource {
    const lineage: LineageEdge[] = fromSourceIds.map((from) => ({ from, kind: 'derive', strength: 1 }));
    const label = fromSourceIds.map(labelOf).reduce<TrustLabel>((acc, l) => maxLabel(acc, l), 'tool');
    return taint('derived', value, taintOptions, { label, lineage });
  }

  function handoff(): TaintHandoff {
    return {
      v: 1,
      depth,
      turn,
      sources: index.sources.map((s) => ({
        id: s.id,
        tool: s.tool,
        text: s.text,
        label: labelOf(s.id),
        injection: s.injection,
        turn: s.turn,
        lineage: s.lineage ?? [],
      })),
      trustedIdentifiers: [...trust.identifiers],
    };
  }

  function absorb(h: TaintHandoff): void {
    assertTaintHandoff(h);
    depth = Math.max(depth, h.depth + 1);
    for (const v of h.trustedIdentifiers) trust.identifiers.add(v.toLowerCase());
    for (const s of h.sources) {
      const existing = index.get(s.id);
      if (existing !== undefined) {
        existing.label = maxLabel(existing.label ?? ownLabel(existing.injection), s.label);
        continue;
      }
      taint(s.tool, s.text, { id: s.id }, { label: s.label, lineage: s.lineage });
    }
  }

  async function approvalCard(call: ToolCall): Promise<ApprovalCard> {
    const decision = check(call);
    const canonicalArgs = canonicalJson(call.args);
    const now = Date.now();
    const card: ApprovalCard = {
      id: randomHex(16),
      // Hashes the canonical text, so it equals `digest(call.args)` wherever receipts compute that.
      digest: await digest(canonicalArgs),
      canonicalArgs,
      toolName: call.toolName,
      ...(call.toolCallId !== undefined ? { toolCallId: call.toolCallId } : {}),
      sink: decision.sink,
      decision,
      rendered: renderApprovalCard(call, decision),
      createdAt: new Date(now).toISOString(),
      expiresAt: '',
    };
    const record = approvals.issue(card);
    card.expiresAt = new Date(record.expiresAt).toISOString();
    return card;
  }

  function codeOf(err: unknown): EnvelopeErrorCode {
    return err instanceof EnvelopeError ? err.code : 'malformed';
  }

  function payloadText(env: unknown): unknown {
    return env !== null && typeof env === 'object' && 'payload' in env ? (env as { payload: unknown }).payload : env;
  }

  async function taintEnvelope(env: unknown, keys: EnvelopeKey | readonly EnvelopeKey[], envOptions: TaintEnvelopeOptions = {}): Promise<TaintEnvelopeResult> {
    const tool = envOptions.tool ?? 'envelope';
    const idOpt = envOptions.id !== undefined ? { id: envOptions.id } : {};
    try {
      const opened = await open(env, keys, envOptions);
      const from = opened.from ?? `envelope:${opened.kid ?? 'key'}`;
      const source = taint(tool, opened.payload, idOpt, { label: opened.label, lineage: [{ from, kind: 'copy', strength: 1 }], attested: true });
      return { source, opened: true };
    } catch (err) {
      // The payload is still registered so its text can be matched, but as blocked provenance.
      const code = codeOf(err);
      const source = taint(tool, payloadText(env), idOpt, { label: 'blocked', lineage: [{ from: `envelope:${code}`, kind: 'copy', strength: 1 }] });
      return { source, opened: false, error: code };
    }
  }

  function withoutSig(entry: MemoryEntry): Omit<MemoryEntry, 'sig'> {
    const body: MemoryEntry = { ...entry };
    delete body.sig;
    return body;
  }

  function memoryKeys(explicit?: EnvelopeKey | readonly EnvelopeKey[]): EnvelopeKey | readonly EnvelopeKey[] | undefined {
    return explicit ?? options.memory?.key;
  }

  async function sealMemoryEntry(entry: MemoryEntry, key?: EnvelopeKey): Promise<MemoryEntry> {
    const configured = memoryKeys(key);
    const signing = Array.isArray(configured) ? (configured as readonly EnvelopeKey[])[0] : (configured as EnvelopeKey | undefined);
    if (signing === undefined) throw new TypeError('sealMemoryEntry: no memory key configured');
    const body = withoutSig(entry);
    const sealed = await seal(body, signing, { label: entry.label, from: `memory:${entry.id}` });
    return { ...body, sig: JSON.stringify(sealed) };
  }

  async function memoryReadSealed(entries: readonly MemoryEntry[], keys?: EnvelopeKey | readonly EnvelopeKey[]): Promise<MemoryReadResult> {
    const verifying = memoryKeys(keys);
    if (verifying === undefined) throw new TypeError('memoryReadSealed: no memory key configured');
    const checked: MemoryEntry[] = [];
    for (const entry of entries) {
      if (!isMemoryEntry(entry)) throw new TypeError('memoryReadSealed: not a v1 MemoryEntry');
      let ok = false;
      if (entry.sig !== undefined) {
        try {
          const env = await open<Omit<MemoryEntry, 'sig'>>(JSON.parse(entry.sig) as unknown, verifying);
          ok = canonicalJson(env.payload) === canonicalJson(withoutSig(entry));
        } catch {
          ok = false;
        }
      }
      // A missing or bad signature means the stored label cannot be trusted: treat the entry as blocked.
      checked.push(ok ? entry : { ...entry, label: 'blocked', lineage: [...entry.lineage, { from: 'envelope:bad-signature', kind: 'copy', strength: 1 }] });
    }
    return memoryRead(checked);
  }

  async function sealHandoff(key: EnvelopeKey, sealOptions: { ttlMs?: number; from?: string } = {}): Promise<Envelope<TaintHandoff>> {
    return seal(handoff(), key, { label: 'tool', ...sealOptions });
  }

  async function absorbSealed(env: unknown, keys: EnvelopeKey | readonly EnvelopeKey[], openOptions: OpenOptions = {}): Promise<AbsorbSealedResult> {
    try {
      const opened = await open<TaintHandoff>(env, keys, openOptions);
      absorb(opened.payload);
      return { opened: true };
    } catch (err) {
      const code = codeOf(err);
      const payload = payloadText(env);
      const claimedDepth = payload !== null && typeof payload === 'object' && typeof (payload as { depth?: unknown }).depth === 'number' ? (payload as { depth: number }).depth : depth;
      depth = Math.max(depth, claimedDepth + 1);
      const source = taint('handoff', payload, {}, { label: 'blocked', lineage: [{ from: `handoff:${code}`, kind: 'copy', strength: 1 }] });
      return { opened: false, error: code, source };
    }
  }

  if (options.inherit !== undefined) absorb(options.inherit);

  const guard: Guard = {
    taint: (source, value, taintOptions) => taint(source, value, taintOptions),
    trust: trustText,
    analyzeUserTurn,
    checkToolCall: check,
    plan(allowedTools) {
      plan = allowedTools === null ? null : new Set(allowedTools);
    },
    memoryRead,
    derive,
    handoff,
    absorb,
    fork(forkOptions = {}) {
      // The child gets its own session and turn counter; only taint state crosses the hop.
      const base: GuardOptions = { ...options };
      delete base.session;
      delete base.inherit;
      return createGuard({ ...base, ...forkOptions, inherit: handoff() });
    },
    approvalCard,
    confirm: (id, digestValue, by) => approvals.confirm(id, digestValue, by),
    wrapTools(tools) {
      // Definitions seen here are compared with the ones pinned, so a runtime redefinition drifts.
      syncDrift(tools as ToolSet);
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
      budget?.nextTurn();
    },
    clear() {
      index = new SourceIndex(maxSources, maxSourceChars);
      trust = { identifiers: new Set(options.trustedIdentifiers?.map((s) => s.toLowerCase())), text: '' };
      plan = null;
      turn = 0;
      depth = 0;
      recent.clear();
      session.clear();
      lock = null;
      identities = new Map();
      drift = new Map();
      budget?.reset();
      if (options.inherit !== undefined) absorb(options.inherit);
    },
    async pin(tools, lockOptions = {}) {
      const next = await pinTools(tools);
      identities = new Map([...toolIdentities(tools)].map(([name, identity]) => [name, identityText(identity)]));
      installLock(next, lockOptions);
      return next;
    },
    lock(next, lockOptions = {}) {
      if (!isToolLock(next)) throw new TypeError('lock: not a v1 ToolLock');
      identities = new Map();
      installLock(next, lockOptions);
    },
    async verify(tools) {
      if (lock === null) return [];
      const found = await verifyTools(tools, lock);
      drift = new Map(found.map((d) => [d.name, d]));
      return found;
    },
    get lockState() {
      return { lock, drift: [...drift.values()], driftAction };
    },
    budget(): BudgetState {
      return budget?.state ?? { turnCalls: 0, toolCalls: {}, repeats: {}, cost: { usd: 0, tokens: 0 }, depth, exceeded: [], onExceed: 'block' };
    },
    recordCost(cost) {
      if (budget === null) return guard.budget();
      return budget.recordCost(cost);
    },
    taintEnvelope,
    sealMemoryEntry,
    memoryReadSealed,
    sealHandoff,
    absorbSealed,
    get session() {
      return session;
    },
    get sources() {
      return index.sources;
    },
    get turn() {
      return turn;
    },
    get depth() {
      return depth;
    },
  };
  return guard;
}
