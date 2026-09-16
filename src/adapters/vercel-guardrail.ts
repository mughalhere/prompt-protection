/**
 * @packageDocumentation
 * @beta Preview tier: may change in a minor release. See docs/API_STABILITY.md.
 */
import { RULES_VERSION } from '../patterns/version.js';
import { digest } from '../utils/digest.js';
import { EXEC_SINKS, EXFIL_SINKS } from '../guard/sinks.js';
import type { Guard, GuardDecision, SinkKind } from '../guard/types.js';
import type { Action, FailMode, FlowSummary } from '../types.js';

/**
 * Reference composition for the Vercel AI SDK: the three-record shape proposed
 * in vercel/ai#13434 (pre-call decision, approval context, post-call receipt)
 * implemented on top of the provenance guard and bridged onto the public
 * `toolApproval`, `onToolExecutionEnd` and `prepareStep` hooks (ai >= 6).
 * Enforcement rides `toolApproval`; `onToolExecutionStart` cannot deny (#15842).
 */

export interface GuardrailContext {
  toolCallId: string;
  toolName: string;
  input: unknown;
  runId?: string;
  stepId?: string | number;
  /** Prior messages; `tool-result` parts are tainted before deciding when `rehydrateFromMessages` is on. */
  messages?: readonly unknown[];
}

export interface GuardrailDecision {
  decision: 'allow' | 'deny' | 'approve';
  /** Human line plus a compact JSON tail (≤ 1 KB) so approval cards can show *why*. */
  reason: string;
  context: {
    policy?: string;
    reasons: string[];
    sink: SinkKind;
    flows: FlowSummary[];
    argsDigest: string;
    rulesVersion: string;
    failMode: FailMode;
    error?: string;
    sourceInjection: Array<{ sourceId: string; tool: string; action: Action; score: number }>;
  };
  guard: GuardDecision;
}

export interface GuardrailReceipt {
  toolCallId: string;
  toolName: string;
  outcome: 'result' | 'error' | 'denied';
  argsDigest: string;
  outputDigest?: string;
  durationMs?: number;
  timestamp: string;
  /** The source id under which the output was tainted, when it was. */
  tainted?: string;
  priorReceiptHash: string | null;
  hash: string;
}

export interface GuardrailProviderOptions {
  runId?: string;
  /** Tool names in the run; needed for `prepareStep` quarantine. */
  tools?: readonly string[];
  /** Taint `tool-result` parts found in `messages` before each decision (serverless-safe, idempotent by id). Default true. */
  rehydrateFromMessages?: boolean;
  /** After a block-scored source in this turn, drop exfil/exec-sink tools from `activeTools`. Default true. */
  quarantine?: boolean;
  failMode?: FailMode;
  sinkOf?: (toolName: string) => SinkKind;
  now?: () => Date;
}

export type ToolApprovalStatusLike =
  | 'not-applicable'
  | 'approved'
  | 'denied'
  | 'user-approval'
  | { type: 'approved' | 'denied' | 'user-approval'; reason?: string };

export interface GuardrailProvider {
  readonly id: 'prompt-protection';
  beforeToolCall(ctx: GuardrailContext): Promise<GuardrailDecision>;
  afterToolCall(input: { toolCallId: string; toolName: string; output?: unknown; error?: unknown; durationMs?: number; input?: unknown }): Promise<GuardrailReceipt>;
  /** Bridge for `generateText({ toolApproval })`. */
  toolApproval(): (options: { toolCall: { toolCallId: string; toolName: string; input: unknown }; messages?: unknown[] }) => Promise<ToolApprovalStatusLike>;
  /** Bridge for `generateText({ onToolExecutionEnd })`: writes a receipt and taints the output (ASI06). */
  onToolExecutionEnd(): (event: {
    toolCall: { toolCallId: string; toolName: string; input: unknown };
    toolOutput: { type: 'tool-result'; output: unknown } | { type: 'tool-error'; error: unknown };
    toolExecutionMs?: number;
  }) => Promise<void>;
  /** Bridge for `generateText({ prepareStep })`: plan lock + quarantine via `activeTools`. */
  prepareStep(): (options: { stepNumber: number; messages?: unknown[] }) => { activeTools?: string[] } | undefined;
  readonly receipts: readonly GuardrailReceipt[];
}

interface ToolResultPart {
  type?: string;
  toolCallId?: string;
  toolName?: string;
  output?: { value?: unknown };
  result?: unknown;
}

function rehydrate(messages: readonly unknown[] | undefined, guard: Guard): void {
  if (!Array.isArray(messages)) return;
  for (const message of messages as Array<{ role?: string; content?: unknown }>) {
    if (message.role !== 'tool' || !Array.isArray(message.content)) continue;
    for (const part of message.content as ToolResultPart[]) {
      if (part.type !== 'tool-result') continue;
      const value = part.output !== undefined ? part.output.value : part.result;
      guard.taint(part.toolName ?? 'tool', value, part.toolCallId !== undefined ? { id: part.toolCallId } : {});
    }
  }
}

function summarize(decision: GuardDecision): FlowSummary[] {
  return decision.flows.map((f) => ({ kind: f.kind, sourceId: f.sourceId, sourceTool: f.sourceTool, path: f.path, strength: f.strength }));
}

function mapDecision(d: GuardDecision): GuardrailDecision['decision'] {
  if (d.action === 'block') return 'deny';
  if (d.requiresConfirmation) return 'approve';
  return 'allow';
}

function statusFor(d: GuardDecision): ToolApprovalStatusLike {
  const reason = d.policy ?? d.reasons[0];
  if (d.action === 'block') return { type: 'denied', ...(reason !== undefined ? { reason } : {}) };
  if (d.requiresConfirmation) return { type: 'user-approval', ...(reason !== undefined ? { reason } : {}) };
  return 'not-applicable';
}

const RANK: Record<string, number> = { denied: 3, 'user-approval': 2, approved: 1, 'not-applicable': 0 };

function normalizeStatus(s: ToolApprovalStatusLike): { type: string; reason?: string } {
  return typeof s === 'string' ? { type: s } : s;
}

/**
 * Composes several `toolApproval` functions, e.g. `@ai-sdk/policy-opa` and this
 * provider, into one: denied > user-approval > approved > not-applicable, reasons joined.
 */
export function composeToolApproval<O>(
  ...fns: Array<(options: O) => ToolApprovalStatusLike | Promise<ToolApprovalStatusLike>>
): (options: O) => Promise<ToolApprovalStatusLike> {
  return async (options) => {
    let top: { type: string; reason?: string } = { type: 'not-applicable' };
    const reasons: string[] = [];
    for (const fn of fns) {
      const s = normalizeStatus(await fn(options));
      if (s.reason) reasons.push(s.reason);
      if ((RANK[s.type] ?? 0) > (RANK[top.type] ?? 0)) top = s;
    }
    if (top.type === 'not-applicable') return 'not-applicable';
    return { type: top.type as 'approved' | 'denied' | 'user-approval', ...(reasons.length > 0 ? { reason: reasons.join('; ') } : {}) };
  };
}

export function createGuardrailProvider(guard: Guard, options: GuardrailProviderOptions = {}): GuardrailProvider {
  const rehydrateFromMessages = options.rehydrateFromMessages ?? true;
  const quarantine = options.quarantine ?? true;
  const failMode = options.failMode ?? 'closed';
  const now = options.now ?? (() => new Date());
  const receipts: GuardrailReceipt[] = [];
  const pendingArgs = new Map<string, string>();

  async function beforeToolCall(ctx: GuardrailContext): Promise<GuardrailDecision> {
    let d: GuardDecision;
    try {
      if (rehydrateFromMessages) rehydrate(ctx.messages, guard);
      d = guard.checkToolCall({ toolName: ctx.toolName, args: ctx.input, toolCallId: ctx.toolCallId });
    } catch (err) {
      d = guard.checkToolCall({ toolName: ctx.toolName, args: {}, toolCallId: ctx.toolCallId });
      d = { ...d, action: failMode === 'open' ? 'allow' : 'block', policy: 'internal-error', reasons: ['internal-error'] };
      d.argsAnalysis = { ...d.argsAnalysis, error: { code: 'internal-error', message: err instanceof Error ? err.message : String(err) } };
    }
    const argsDigest = await digest(ctx.input ?? {});
    pendingArgs.set(ctx.toolCallId, argsDigest);
    const sourceInjection = d.flows
      .map((f) => guard.sources.find((s) => s.id === f.sourceId))
      .filter((s): s is NonNullable<typeof s> => s !== undefined)
      .map((s) => ({ sourceId: s.id, tool: s.tool, action: s.injection.action, score: s.injection.score }));
    const context: GuardrailDecision['context'] = {
      ...(d.policy !== undefined ? { policy: d.policy } : {}),
      reasons: d.reasons,
      sink: d.sink,
      flows: summarize(d),
      argsDigest,
      rulesVersion: RULES_VERSION,
      failMode,
      ...(d.argsAnalysis.error ? { error: d.argsAnalysis.error.message } : {}),
      sourceInjection,
    };
    const decision = mapDecision(d);
    const human =
      decision === 'allow'
        ? `allow ${ctx.toolName}`
        : `${decision === 'deny' ? 'deny' : 'needs approval'} ${ctx.toolName}: ${d.policy ?? d.reasons[0] ?? 'policy'}` +
          (context.flows.length > 0 ? `, ${context.flows.map((f) => `${f.kind} from ${f.sourceTool} → ${f.path}`).join(', ')}` : '');
    const tail = JSON.stringify({ policy: context.policy, sink: context.sink, flows: context.flows, argsDigest }).slice(0, 1024);
    return { decision, reason: `${human} ${tail}`, context, guard: d };
  }

  async function afterToolCall(input: { toolCallId: string; toolName: string; output?: unknown; error?: unknown; durationMs?: number; input?: unknown }): Promise<GuardrailReceipt> {
    const prior = receipts[receipts.length - 1]?.hash ?? null;
    const argsDigest = pendingArgs.get(input.toolCallId) ?? (await digest(input.input ?? {}));
    pendingArgs.delete(input.toolCallId);
    const last = guard.lastDecision(input.toolCallId);
    const outcome: GuardrailReceipt['outcome'] = last?.action === 'block' ? 'denied' : input.error !== undefined ? 'error' : 'result';
    const base: Omit<GuardrailReceipt, 'hash'> = {
      toolCallId: input.toolCallId,
      toolName: input.toolName,
      outcome,
      argsDigest,
      timestamp: now().toISOString(),
      priorReceiptHash: prior,
    };
    if (input.durationMs !== undefined) base.durationMs = input.durationMs;
    if (outcome === 'result' && input.output !== undefined) {
      base.outputDigest = await digest(input.output);
      const write = guard.taintMemoryWrite(input.toolName, input.output, { id: input.toolCallId });
      base.tainted = write.source.id;
    }
    const receipt: GuardrailReceipt = { ...base, hash: await digest(base) };
    receipts.push(receipt);
    return receipt;
  }

  const sinkOf = options.sinkOf;

  return {
    id: 'prompt-protection',
    beforeToolCall,
    afterToolCall,
    toolApproval: () => async ({ toolCall, messages }) => {
      const d = await beforeToolCall({ toolCallId: toolCall.toolCallId, toolName: toolCall.toolName, input: toolCall.input, ...(messages !== undefined ? { messages } : {}) });
      return statusFor(d.guard);
    },
    onToolExecutionEnd: () => async ({ toolCall, toolOutput, toolExecutionMs }) => {
      await afterToolCall({
        toolCallId: toolCall.toolCallId,
        toolName: toolCall.toolName,
        input: toolCall.input,
        ...(toolOutput.type === 'tool-result' ? { output: toolOutput.output } : { error: toolOutput.error }),
        ...(toolExecutionMs !== undefined ? { durationMs: toolExecutionMs } : {}),
      });
    },
    prepareStep: () => ({ messages }) => {
      if (rehydrateFromMessages) rehydrate(messages, guard);
      const tools = options.tools;
      if (tools === undefined) return undefined;
      const blockedThisTurn = quarantine && guard.sources.some((s) => s.turn === guard.turn && s.injection.action === 'block');
      if (!blockedThisTurn) return undefined;
      const resolve = sinkOf ?? ((name: string) => guard.checkToolCall({ toolName: name, args: {} }).sink);
      const active = tools.filter((name) => {
        const sink = resolve(name);
        return !EXFIL_SINKS.has(sink) && !EXEC_SINKS.has(sink) && sink !== 'payment';
      });
      return { activeTools: active };
    },
    get receipts() {
      return receipts;
    },
  };
}
