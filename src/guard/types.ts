import type { IdentifierKind } from '../utils/identifiers.js';
import type { ShingleSet } from '../utils/shingle.js';
import type {
  Action,
  AnalysisResult,
  AnalyzeOptions,
  FailMode,
  LoggingOptions,
  ThreatCategory,
} from '../types.js';
import type { ProtectionSession, ProtectionSessionOptions } from '../session.js';
import type { AnyString } from '../types.js';
import type { DecisionReason } from './reasons.js';
import type { LineageEdge, MemoryEntry, MemoryReadResult, TrustLabel } from './memory.js';
import type { TaintHandoff } from './handoff.js';
import type { ApprovalCard, ApprovalOptions, ApprovalRecord, ApprovalState } from './approval.js';
import type { LockView, ToolDrift, ToolLock, ToolSet } from './pin.js';
import type { BudgetOptions, BudgetState } from './budgets.js';
import type { SpotlightBoundary } from '../spotlight/index.js';

/** Where a tool's side effects land. `none` marks read-only tools. */
export type SinkKind =
  | 'network' | 'email' | 'message' | 'file-write' | 'exec' | 'payment' | 'none'
  | 'unknown' // under a lock: unannotated tool the heuristics call `none`; treated as exfil and exec
  | AnyString; // open union: a minor may add sinks (see docs/API_STABILITY.md)

/** How a tool-result fragment was detected inside a tool-call argument. */
export type FlowKind = 'exact' | 'identifier' | 'content' | AnyString;

export interface Flow {
  kind: FlowKind;
  /** For `identifier` flows: what kind of identifier matched (`handle` = verbatim destination value). */
  identifierKind?: IdentifierKind | 'handle';
  /** `TaintedSource.id` of the source the argument fragment came from. */
  sourceId: string;
  /** Tool that produced the source. */
  sourceTool: string;
  /** Dotted path of the argument leaf, e.g. `args.url` or `args.items[0].to`. */
  path: string;
  /** Matched identifier or a preview of the matched fragment. */
  value: string;
  /** 0–1 confidence; `exact` 1.0, `identifier` 0.9, `content` = containment ratio. */
  strength: number;
}

export interface SourceInjection {
  score: number;
  action: Action;
  categories: ThreatCategory[];
  mlProbability?: number;
}

export interface TaintedSource {
  id: string;
  tool: string;
  /** Stringified tool result (truncated to `maxSourceChars`). */
  text: string;
  normalized: string;
  shingles: ShingleSet;
  /** Lowercased identifier values (→ kind) from raw, defanged and decoded text. */
  identifiers: Map<string, IdentifierKind>;
  injection: SourceInjection;
  /** Value of the guard's turn counter when the source was registered. */
  turn: number;
  timestamp: number;
  /** Provenance label; absent means `tool` (or `blocked` when the source scored as injection). */
  label?: TrustLabel;
  /** Where the value came from (memory reads, handoffs, `derive`). */
  lineage?: LineageEdge[];
}

export interface ToolCall {
  toolName: string;
  args: unknown;
  toolCallId?: string;
}

export interface GuardDecision {
  action: Action;
  /** True when a `confirm` policy fired: `action` is `flag` and a human should approve. */
  requiresConfirmation: boolean;
  toolName: string;
  toolCallId?: string;
  sink: SinkKind;
  flows: Flow[];
  /** Reason codes, highest severity first (policy ids plus `approved`). */
  reasons: DecisionReason[];
  /** The policy that decided the action, when any fired. */
  policy?: string;
  /** Scan of the argument text itself, with synthetic `data-flow` matches for flows. */
  argsAnalysis: AnalysisResult;
  /** Sub-agent depth of the deciding guard (0 = root). */
  depth: number;
  /** What the approval store said about this call, when a confirmed record applied. */
  approval?: ApprovalState;
  /** Lock state for this tool, when the guard is locked. */
  lock?: LockView;
  /** Budget state after counting this attempt, when budgets are configured. */
  budget?: BudgetState;
  /** In observe mode: the verdict that would have been enforced (`action` is then `allow`). */
  observedAction?: Action;
  observedRequiresConfirmation?: boolean;
}

export type PolicyAction = 'allow' | 'flag' | 'confirm' | 'block';

export interface PolicyContext {
  call: ToolCall;
  sink: SinkKind;
  flows: Flow[];
  /** Every registered source, oldest first. */
  sources: readonly TaintedSource[];
  /** Sources registered during the current turn. */
  turnSources: readonly TaintedSource[];
  argsAnalysis: AnalysisResult;
  /** Tool allowlist from `guard.plan()`, or null when unlocked. */
  plan: ReadonlySet<string> | null;
  /** The call names ≥1 destination (recipient/URL/account) and the user authored all of them. */
  destinationTrusted: boolean;
  sourceById: (id: string) => TaintedSource | undefined;
  /** Provenance label of a source (`blocked` when it scored as injection or inherited that label). */
  labelOf: (sourceId: string) => TrustLabel;
  /** Sub-agent depth of this guard. */
  depth: number;
  /** Confirmed approval that applies to this call, or null. */
  approval: ApprovalState | null;
  /** Lock state for this tool (`UNLOCKED` when no lock is installed). */
  lock: LockView;
  /** Budget state after this attempt was counted, or null when budgets are off. */
  budget: BudgetState | null;
  /** Whether `requireLock` is set on the guard. */
  requireLock: boolean;
}

export interface GuardPolicy {
  id: string;
  /** Return the action this policy demands, or `null` when it does not apply. */
  evaluate(ctx: PolicyContext): PolicyAction | null;
}

export type SinkResolver = (toolName: string) => SinkKind | undefined;

export type SpotlightMode = 'delimit' | 'datamark' | 'encode';

export interface GuardSpotlightOptions {
  mode: SpotlightMode;
  /** Fixed marker; generated per guard when omitted. */
  marker?: string;
}

export interface GuardOptions extends LoggingOptions {
  /** Reuse an existing session; the guard creates one otherwise. */
  session?: ProtectionSession;
  /** Options for the guard-owned session and for argument scans. */
  analyzeOptions?: ProtectionSessionOptions;
  /** Tool name → sink. A map falls back to the defaults for unlisted tools. */
  sinks?: Record<string, SinkKind> | SinkResolver;
  /** Replaces the default policy list. */
  policies?: GuardPolicy[];
  /** Word-shingle containment needed for a `content` flow. Default 0.5. */
  minContainment?: number;
  /** Char-shingle containment fallback for short or code-like leaves. Default 0.6. */
  minCharContainment?: number;
  /** Ring-buffer limits. Defaults 64 sources / 200 000 chars. */
  maxSources?: number;
  maxSourceChars?: number;
  /** Identifiers the user is known to have authored (pre-trusted). */
  trustedIdentifiers?: string[];
  /** Spotlight tool results returned through `wrapTools`; a `createBoundary()` result reuses its marker. */
  spotlight?: SpotlightMode | GuardSpotlightOptions | SpotlightBoundary;
  /** Verdict when the guard itself throws: `'closed'` (default) blocks, `'open'` allows. */
  failMode?: FailMode;
  /** Approval-record TTL and ring size (`guard.approvalCard` / `guard.confirm`). */
  approvals?: ApprovalOptions;
  /** Memory-entry limits (`guard.memoryRead`). */
  memory?: { maxEntries?: number };
  /** Taint state from a parent guard; absorbed at construction (`guard.fork` sets this). */
  inherit?: TaintHandoff;
  /** Block every call until `guard.pin` / `guard.lock` has installed a lock. Default false. */
  requireLock?: boolean;
  /**
   * Under a lock, what an unannotated tool the name heuristics call `none` resolves to:
   * `destructive` (default) → `unknown` (exfil + exec), `heuristic` → `none`.
   */
  annotationsDefault?: 'destructive' | 'heuristic';
  /** Call, repeat, depth and cost limits. Off by default. */
  budgets?: BudgetOptions;
  /**
   * Option bundle: `balanced` (default policies, identical to no preset), `strict` (confirm on
   * untrusted destinations, args-injection blocks, budgets on, lower containment), `permissive`
   * (no same-turn flags, payment flags, heuristic annotations). Explicit options always win.
   */
  preset?: 'strict' | 'balanced' | 'permissive';
  /** `observe` records the verdict in `observedAction` and never enforces; default `enforce`. */
  mode?: 'enforce' | 'observe';
}

export interface LockOptions {
  /** Verdict for a tool whose definition drifted from the lock. Default `block`. */
  drift?: 'block' | 'confirm';
}

export interface LockState {
  lock: ToolLock | null;
  drift: ToolDrift[];
  driftAction: 'block' | 'confirm';
}

export interface TaintOptions {
  /** Stable id (e.g. a tool-call id); re-registering the same id is a no-op. */
  id?: string;
}

export interface MemoryWriteOptions extends TaintOptions {
  /** `reject-blocked` (default) refuses to store injection-scored results; `annotate` stores and reports. */
  policy?: 'reject-blocked' | 'annotate';
  /** Source ids this value was derived from (`copy` edges, strength 1). Auto-detected by containment otherwise. */
  derivedFrom?: string[];
  /** Application key the entry is stored under. */
  key?: string;
  /** Overrides the derived label (only ever raises it). */
  label?: TrustLabel;
}

export interface MemoryWriteResult {
  source: TaintedSource;
  action: Action;
  /** Whether the caller should persist the value. */
  store: boolean;
  /** Spotlit form of the text when the guard has `spotlight` configured, persist this, not the raw text. */
  spotlit?: string;
  /** Lineage record to persist next to the value; feed it back through `memoryRead`. */
  entry: MemoryEntry;
}

export type ToolApprovalOutcome =
  | 'not-applicable'
  | { type: 'approved' | 'denied' | 'user-approval'; reason?: string };

export interface ToolApprovalInput {
  toolCall: { toolName: string; input: unknown; toolCallId?: string };
}

/** Minimal tool shape shared by the Vercel AI SDK and MCP-style tool maps. */
export interface WrappableTool {
  execute?: (input: unknown, options?: unknown) => unknown;
}

export interface Guard {
  /** Registers a tool result as untrusted and scores it for injection. */
  taint(source: string, value: unknown, options?: TaintOptions): TaintedSource;
  /** Marks identifiers and text the user authored as trusted (never a flow). */
  trust(text: string): void;
  /** Scores the user turn through the session and trusts its content. */
  analyzeUserTurn(prompt: string, options?: AnalyzeOptions): AnalysisResult;
  checkToolCall(call: ToolCall): GuardDecision;
  /** Locks the tool set for Plan-Then-Execute; `null` unlocks. */
  plan(allowedTools: readonly string[] | null): void;
  /** Wraps `execute` so calls are checked first and results tainted after. */
  wrapTools<T extends Record<string, WrappableTool>>(tools: T): T;
  /** Approval function for the Vercel AI SDK `toolApproval` option. */
  vercelToolApproval(): (input: ToolApprovalInput) => ToolApprovalOutcome;
  /**
   * Taints a tool result that is about to be persisted to agent memory (OWASP ASI06).
   * `store` is false when the source scores as injection under `reject-blocked`.
   */
  taintMemoryWrite(source: string, value: unknown, options?: MemoryWriteOptions): MemoryWriteResult;
  /** Most recent decision for a tool-call id (ring of 64), for approval UIs and receipts. */
  lastDecision(toolCallId: string): GuardDecision | undefined;
  /**
   * Registers persisted memory entries as tainted sources, re-scored under the current rules and
   * carrying their stored label and lineage (`lineage-untrusted` fires on a `blocked` lineage).
   */
  memoryRead(entries: readonly MemoryEntry[]): MemoryReadResult;
  /** Registers an app-visible derivation (summary, extracted field) that inherits its parents' labels. */
  derive(value: unknown, fromSourceIds: readonly string[], options?: TaintOptions): TaintedSource;
  /** Serialises taint state for a sub-agent's guard. */
  handoff(): TaintHandoff;
  /** Absorbs a parent's taint state; depth becomes `max(depth, handoff.depth + 1)`. Throws on malformed input. */
  absorb(handoff: TaintHandoff): void;
  /** `createGuard({ ...options, inherit: this.handoff() })`. */
  fork(options?: GuardOptions): Guard;
  /** Checks the call and issues an approval card whose `digest` a UI must echo back to `confirm`. */
  approvalCard(call: ToolCall): Promise<ApprovalCard>;
  /** Approves a card; a digest that differs from the card throws `ApprovalMismatchError`. */
  confirm(id: string, digest: string, by?: string): ApprovalRecord;
  nextTurn(): void;
  clear(): void;
  readonly session: ProtectionSession;
  readonly sources: readonly TaintedSource[];
  readonly turn: number;
  /** Sub-agent depth (0 = root). */
  readonly depth: number;
  /** Digests the tool definitions (never `execute`), installs the lock and returns it for persisting. */
  pin(tools: ToolSet, options?: LockOptions): Promise<ToolLock>;
  /** Installs a persisted lock. Drift is detected on the next `verify` (or `wrapTools` after `pin`). */
  lock(lock: ToolLock, options?: LockOptions): void;
  /** Re-checks current definitions against the lock; the result drives `tool-drift` until the next call. */
  verify(tools: ToolSet): Promise<ToolDrift[]>;
  readonly lockState: LockState;
  /** Budget state so far (all zeros when budgets are off). */
  budget(): BudgetState;
  recordCost(cost: { usd?: number; tokens?: number }): BudgetState;
}
