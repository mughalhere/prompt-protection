import { canonicalJson, digest } from '../utils/canonical.js';
import { RULES_VERSION } from '../patterns/version.js';

/** MCP-style tool annotations. Only `readOnlyHint` changes a sink, and only under a lock. */
export interface ToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  title?: string;
}

/** Structural view of a tool definition (MCP, Vercel AI SDK, OpenAI function shapes). */
export interface ToolLike {
  name?: string;
  description?: string;
  inputSchema?: unknown;
  parameters?: unknown;
  annotations?: ToolAnnotations;
}

export type ToolSet = Readonly<Record<string, ToolLike>> | readonly ToolLike[];

export interface PinnedTool {
  digest: string;
  annotations?: ToolAnnotations;
}

export interface ToolLock {
  v: 1;
  algo: 'sha256' | 'fnv1a64';
  createdAt: string;
  rulesVersion: string;
  tools: Record<string, PinnedTool>;
}

export interface ToolDrift {
  name: string;
  /** `changed`: definition differs; `unlisted`: present now, absent from the lock; `missing`: pinned, absent now. */
  kind: 'changed' | 'unlisted' | 'missing';
  expected?: string;
  actual?: string;
}

/** What a pinned tool is: name, description (poisoning lives there), schema and annotations. Never `execute`. */
export interface ToolIdentity {
  name: string;
  description: string;
  schema: unknown;
  annotations: ToolAnnotations | null;
}

export function toolIdentity(name: string, tool: ToolLike): ToolIdentity {
  return {
    name,
    description: tool.description ?? '',
    schema: tool.inputSchema ?? tool.parameters ?? null,
    annotations: tool.annotations ?? null,
  };
}

/** Name → identity; arrays use each tool's own `name`, maps use the key. */
export function toolIdentities(tools: ToolSet): Map<string, ToolIdentity> {
  const out = new Map<string, ToolIdentity>();
  if (Array.isArray(tools)) {
    for (const t of tools as readonly ToolLike[]) {
      if (typeof t.name === 'string' && t.name.length > 0) out.set(t.name, toolIdentity(t.name, t));
    }
  } else {
    for (const [name, t] of Object.entries(tools as Record<string, ToolLike>)) out.set(name, toolIdentity(name, t));
  }
  return out;
}

/** Canonical text of an identity; equal text ⇔ equal digest, so sync compares can use it. */
export function identityText(identity: ToolIdentity): string {
  return canonicalJson(identity);
}

export async function pinTools(tools: ToolSet): Promise<ToolLock> {
  const entries: Record<string, PinnedTool> = {};
  let algo: ToolLock['algo'] = 'sha256';
  for (const [name, identity] of toolIdentities(tools)) {
    const d = await digest(identityText(identity));
    if (d.startsWith('fnv1a64:')) algo = 'fnv1a64';
    entries[name] = { digest: d, ...(identity.annotations !== null ? { annotations: identity.annotations } : {}) };
  }
  return { v: 1, algo, createdAt: new Date().toISOString(), rulesVersion: RULES_VERSION, tools: entries };
}

/** Drift between current definitions and a lock; empty array means byte-identical identities. */
export async function verifyTools(tools: ToolSet, lock: ToolLock): Promise<ToolDrift[]> {
  const drift: ToolDrift[] = [];
  const current = toolIdentities(tools);
  for (const [name, identity] of current) {
    const pinned = lock.tools[name];
    const actual = await digest(identityText(identity));
    if (pinned === undefined) drift.push({ name, kind: 'unlisted', actual });
    else if (pinned.digest !== actual) drift.push({ name, kind: 'changed', expected: pinned.digest, actual });
  }
  for (const name of Object.keys(lock.tools)) {
    if (current.has(name)) continue;
    const expected = lock.tools[name]?.digest;
    drift.push({ name, kind: 'missing', ...(expected !== undefined ? { expected } : {}) });
  }
  return drift;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export function isToolLock(v: unknown): v is ToolLock {
  if (!isRecord(v) || v.v !== 1) return false;
  if (v.algo !== 'sha256' && v.algo !== 'fnv1a64') return false;
  if (typeof v.createdAt !== 'string' || typeof v.rulesVersion !== 'string' || !isRecord(v.tools)) return false;
  return Object.values(v.tools).every((t) => isRecord(t) && typeof t.digest === 'string');
}

/** Lock state as the check pipeline sees it for one tool name. */
export interface LockView {
  locked: boolean;
  /** The tool is in the lock. Always true when unlocked. */
  listed: boolean;
  drift: ToolDrift | null;
  annotations: ToolAnnotations | null;
  /** Verdict `tool-drift` yields; from `LockOptions.drift`. */
  driftAction?: 'block' | 'confirm';
}

export const UNLOCKED: LockView = { locked: false, listed: true, drift: null, annotations: null };
