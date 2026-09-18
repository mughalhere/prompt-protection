import type { AnyString } from '../types.js';
import type { SourceInjection, TaintedSource } from './types.js';

/** Provenance rank of a value; higher is less trusted. Unknown labels rank as `untrusted`. */
export type TrustLabel = 'system' | 'user' | 'tool' | 'untrusted' | 'blocked' | AnyString;

export const TRUST_LABEL_RANK: Readonly<Record<string, number>> = {
  system: 0,
  user: 1,
  tool: 2,
  untrusted: 3,
  blocked: 4,
};

const UNTRUSTED_RANK = 3;

export function rankOf(label: TrustLabel): number {
  return TRUST_LABEL_RANK[label] ?? UNTRUSTED_RANK;
}

export function maxLabel(first: TrustLabel, ...rest: TrustLabel[]): TrustLabel {
  let out = first;
  for (const l of rest) if (rankOf(l) > rankOf(out)) out = l;
  return out;
}

export type LineageKind = 'copy' | 'derive' | 'summarize' | 'read' | AnyString;

export interface LineageEdge {
  /** Source id (or memory entry id) the value came from. */
  from: string;
  kind: LineageKind;
  /** 0–1; edges at or above `STRONG_EDGE` propagate the parent's label. */
  strength: number;
}

/** Edges below this strength are recorded but never propagate a label. */
export const STRONG_EDGE = 0.5;
/** Auto-detected edges below this are dropped as noise. */
export const MIN_EDGE = 0.1;

export interface MemoryEntry {
  v: 1;
  id: string;
  key?: string;
  value: string;
  label: TrustLabel;
  sourceIds: string[];
  lineage: LineageEdge[];
  injection: SourceInjection;
  rulesVersion: string;
  turn: number;
  ts: string;
  /** Reserved for the 4.4 signed envelope. */
  sig?: string;
}

export interface MemoryReadResult {
  sources: TaintedSource[];
  /** Highest label across the entries read. */
  label: TrustLabel;
  edges: LineageEdge[];
  /** Highest-scoring injection result across the entries (re-scored under the current rules). */
  injection: SourceInjection;
}

/** Max label over strong edges, then max with the value's own label. */
export function deriveLabel(
  edges: readonly LineageEdge[],
  labelOf: (id: string) => TrustLabel | undefined,
  own: TrustLabel,
): TrustLabel {
  let out = own;
  for (const e of edges) {
    if (e.strength < STRONG_EDGE) continue;
    const parent = labelOf(e.from);
    if (parent !== undefined && rankOf(parent) > rankOf(out)) out = parent;
  }
  return out;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isEdge(v: unknown): v is LineageEdge {
  return isRecord(v) && typeof v.from === 'string' && typeof v.kind === 'string' && typeof v.strength === 'number';
}

/** Structural check for app-supplied JSON; anything else is rejected rather than trusted. */
export function isMemoryEntry(v: unknown): v is MemoryEntry {
  if (!isRecord(v) || v.v !== 1) return false;
  if (typeof v.id !== 'string' || typeof v.value !== 'string' || typeof v.label !== 'string') return false;
  if (!Array.isArray(v.sourceIds) || !v.sourceIds.every((s) => typeof s === 'string')) return false;
  if (!Array.isArray(v.lineage) || !v.lineage.every(isEdge)) return false;
  if (!isRecord(v.injection) || typeof v.injection.score !== 'number' || typeof v.injection.action !== 'string') return false;
  return typeof v.rulesVersion === 'string' && typeof v.turn === 'number' && typeof v.ts === 'string';
}
