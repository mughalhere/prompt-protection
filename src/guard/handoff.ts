import type { LineageEdge, TrustLabel } from './memory.js';
import type { SourceInjection } from './types.js';

export interface HandoffSource {
  id: string;
  tool: string;
  text: string;
  label: TrustLabel;
  injection: SourceInjection;
  turn: number;
  lineage: LineageEdge[];
}

/** Taint state a parent guard passes to a sub-agent's guard (`guard.handoff()` → `guard.absorb()`). */
export interface TaintHandoff {
  v: 1;
  /** Hops from the root agent; the receiving guard becomes `depth + 1`. */
  depth: number;
  turn: number;
  sources: HandoffSource[];
  trustedIdentifiers: string[];
}

export class HandoffError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = 'HandoffError';
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isSource(v: unknown): v is HandoffSource {
  return (
    isRecord(v) &&
    typeof v.id === 'string' &&
    typeof v.tool === 'string' &&
    typeof v.text === 'string' &&
    typeof v.label === 'string' &&
    isRecord(v.injection) &&
    typeof v.turn === 'number' &&
    Array.isArray(v.lineage)
  );
}

export function isTaintHandoff(v: unknown): v is TaintHandoff {
  return (
    isRecord(v) &&
    v.v === 1 &&
    typeof v.depth === 'number' &&
    typeof v.turn === 'number' &&
    Array.isArray(v.sources) &&
    v.sources.every(isSource) &&
    Array.isArray(v.trustedIdentifiers) &&
    v.trustedIdentifiers.every((s) => typeof s === 'string')
  );
}

/** Throws `HandoffError` on anything but a well-formed v1 handoff; a guard never absorbs what it cannot read. */
export function assertTaintHandoff(v: unknown): asserts v is TaintHandoff {
  if (!isTaintHandoff(v)) throw new HandoffError('not a v1 TaintHandoff');
}
