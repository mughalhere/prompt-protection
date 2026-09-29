import { DESTINATION_KEYS, keyOf } from './provenance.js';
import type { DecisionReason } from './reasons.js';
import type { GuardDecision, SinkKind, ToolCall } from './types.js';

export interface ApprovalRecord {
  id: string;
  toolName: string;
  toolCallId?: string;
  /** `canonicalJson(call.args)` at card time; checks compare this string, never a hash. */
  canonicalArgs: string;
  /** `digest(canonicalArgs)` — what the UI must echo back to `confirm`. */
  digest: string;
  createdAt: number;
  expiresAt: number;
  confirmedAt?: number;
  by?: string;
  /** Set when an approved call has passed the guard once; a record is single-use. */
  usedAt?: number;
}

export type ApprovalStatus = 'approved' | 'mismatch' | 'expired';

/** What the check pipeline learned about a call from the approval store. */
export interface ApprovalState {
  id: string;
  status: ApprovalStatus;
}

export type ApprovalFieldKind = 'destination' | 'payload' | 'other';

export interface ApprovalField {
  path: string;
  value: string;
  /** The value (or part of it) came from a tainted source. */
  tainted: boolean;
  sourceTool?: string;
  kind: ApprovalFieldKind;
}

export interface ApprovalCard {
  id: string;
  digest: string;
  canonicalArgs: string;
  toolName: string;
  toolCallId?: string;
  sink: SinkKind;
  decision: GuardDecision;
  rendered: {
    title: string;
    risk: 'low' | 'medium' | 'high';
    reasons: DecisionReason[];
    summary: string;
    fields: ApprovalField[];
  };
  createdAt: string;
  expiresAt: string;
}

export interface ApprovalOptions {
  /** How long a confirmed approval stays valid. Default 10 minutes. */
  ttlMs?: number;
  /** Records kept (ring). Default 64. */
  maxPending?: number;
  /** Clock, for tests. */
  now?: () => number;
}

export type ApprovalMismatchCode = 'digest' | 'unknown-id' | 'expired';

export class ApprovalMismatchError extends Error {
  readonly code: ApprovalMismatchCode;
  readonly id: string;
  constructor(code: ApprovalMismatchCode, id: string, message: string) {
    super(message);
    this.name = 'ApprovalMismatchError';
    this.code = code;
    this.id = id;
  }
}

export interface ApprovalStore {
  issue(card: ApprovalCard): ApprovalRecord;
  /** Marks a card approved; the digest must be the one the card carried. */
  confirm(id: string, digest: string, by?: string): ApprovalRecord;
  /** Sync; compares canonical strings. `null` when no confirmed record applies. */
  lookup(call: ToolCall, canonicalArgs: string): ApprovalState | null;
  /** Spends an approved record after the call it covered passed. */
  consume(id: string): void;
  get(id: string): ApprovalRecord | undefined;
  readonly size: number;
}

export const DEFAULT_APPROVAL_TTL_MS = 10 * 60 * 1000;
export const DEFAULT_APPROVAL_MAX = 64;

export function createApprovalStore(options: ApprovalOptions = {}): ApprovalStore {
  const ttl = options.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
  const max = options.maxPending ?? DEFAULT_APPROVAL_MAX;
  const now = options.now ?? Date.now;
  const records = new Map<string, ApprovalRecord>();
  const byCallId = new Map<string, string>();

  function evict(): void {
    while (records.size > max) {
      const oldest = records.keys().next().value as string;
      const rec = records.get(oldest);
      records.delete(oldest);
      if (rec?.toolCallId !== undefined && byCallId.get(rec.toolCallId) === oldest) byCallId.delete(rec.toolCallId);
    }
  }

  function live(rec: ApprovalRecord, at: number): boolean {
    return rec.confirmedAt !== undefined && rec.usedAt === undefined && at <= rec.expiresAt;
  }

  return {
    issue(card) {
      const at = now();
      const rec: ApprovalRecord = {
        id: card.id,
        toolName: card.toolName,
        ...(card.toolCallId !== undefined ? { toolCallId: card.toolCallId } : {}),
        canonicalArgs: card.canonicalArgs,
        digest: card.digest,
        createdAt: at,
        expiresAt: at + ttl,
      };
      records.delete(rec.id);
      records.set(rec.id, rec);
      if (rec.toolCallId !== undefined) byCallId.set(rec.toolCallId, rec.id);
      evict();
      return rec;
    },
    confirm(id, digest, by) {
      const rec = records.get(id);
      if (rec === undefined) throw new ApprovalMismatchError('unknown-id', id, `no approval card ${id}`);
      if (digest !== rec.digest) {
        throw new ApprovalMismatchError('digest', id, `approval ${id}: digest does not match the card`);
      }
      const at = now();
      if (at > rec.expiresAt) throw new ApprovalMismatchError('expired', id, `approval ${id} expired`);
      rec.confirmedAt = at;
      if (by !== undefined) rec.by = by;
      return rec;
    },
    lookup(call, canonicalArgs) {
      const at = now();
      if (call.toolCallId !== undefined) {
        const id = byCallId.get(call.toolCallId);
        const rec = id !== undefined ? records.get(id) : undefined;
        if (rec !== undefined && rec.confirmedAt !== undefined) {
          if (rec.canonicalArgs !== canonicalArgs) return { id: rec.id, status: 'mismatch' };
          return { id: rec.id, status: live(rec, at) ? 'approved' : 'expired' };
        }
      }
      let stale: ApprovalState | null = null;
      for (const rec of [...records.values()].reverse()) {
        if (rec.toolName !== call.toolName || rec.confirmedAt === undefined || rec.canonicalArgs !== canonicalArgs) continue;
        if (live(rec, at)) return { id: rec.id, status: 'approved' };
        stale ??= { id: rec.id, status: 'expired' };
      }
      return stale;
    },
    consume(id) {
      const rec = records.get(id);
      if (rec !== undefined) rec.usedAt = now();
    },
    get: (id) => records.get(id),
    get size() {
      return records.size;
    },
  };
}

const PAYLOAD_KEYS = new Set(['body', 'content', 'text', 'message', 'command', 'cmd', 'script', 'payload', 'data', 'html', 'code', 'query', 'sql']);

function fieldKind(path: string, value: string): ApprovalFieldKind {
  const key = keyOf(path);
  if (DESTINATION_KEYS.has(key)) return 'destination';
  if (PAYLOAD_KEYS.has(key) || value.length > 64) return 'payload';
  return 'other';
}

function scalarLeaves(args: unknown, path: string, out: Array<{ path: string; value: string }>, depth = 0): void {
  if (depth > 32) return;
  if (Array.isArray(args)) {
    args.forEach((item, i) => scalarLeaves(item, `${path}[${i}]`, out, depth + 1));
  } else if (args !== null && typeof args === 'object') {
    for (const [k, v] of Object.entries(args as Record<string, unknown>)) scalarLeaves(v, `${path}.${k}`, out, depth + 1);
  } else if (args !== undefined && typeof args !== 'function') {
    out.push({ path, value: typeof args === 'string' ? args : String(args) });
  }
}

function riskOf(decision: GuardDecision): ApprovalCard['rendered']['risk'] {
  if (decision.action === 'block') return 'high';
  if (decision.requiresConfirmation || decision.action === 'flag') return 'medium';
  return 'low';
}

/** Human-readable card body; tainted fields are the paths a flow landed on. */
export function renderApprovalCard(call: ToolCall, decision: GuardDecision): ApprovalCard['rendered'] {
  const leaves: Array<{ path: string; value: string }> = [];
  scalarLeaves(call.args, 'args', leaves);
  const fields: ApprovalField[] = leaves.map((leaf) => {
    const flow = decision.flows.find((f) => f.path === leaf.path);
    return {
      path: leaf.path,
      value: leaf.value.length > 200 ? `${leaf.value.slice(0, 197)}...` : leaf.value,
      tainted: flow !== undefined,
      ...(flow !== undefined ? { sourceTool: flow.sourceTool } : {}),
      kind: fieldKind(leaf.path, leaf.value),
    };
  });
  const tainted = fields.filter((f) => f.tainted);
  const tools = [...new Set(decision.flows.map((f) => f.sourceTool))];
  const summary =
    `${decision.action}${decision.requiresConfirmation ? ' (needs approval)' : ''}; ` +
    `${tainted.length} tainted field${tainted.length === 1 ? '' : 's'}` +
    (tools.length > 0 ? ` from ${tools.join(', ')}` : '');
  return {
    title: `${call.toolName} → ${decision.sink}`,
    risk: riskOf(decision),
    reasons: [...decision.reasons],
    summary,
    fields,
  };
}
