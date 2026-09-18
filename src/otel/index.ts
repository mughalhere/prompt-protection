/**
 * @packageDocumentation
 * @beta Preview tier: may change in a minor release. See docs/API_STABILITY.md.
 */
import type { ProtectionEvent, ProtectionLogger } from '../types.js';
import { RULES_VERSION } from '../patterns/version.js';

/** Attribute names used on spans, events and the decisions counter. */
export const OTEL_ATTR = {
  decision: 'pp.decision',
  direction: 'pp.direction',
  type: 'pp.type',
  score: 'pp.score',
  severity: 'pp.severity',
  policy: 'pp.policy',
  reasons: 'pp.reasons',
  sink: 'pp.sink',
  flows: 'pp.flows',
  flowKinds: 'pp.flow.kinds',
  toolName: 'pp.tool.name',
  toolCallId: 'pp.tool.call_id',
  ruleIds: 'pp.rule_ids',
  categories: 'pp.categories',
  rulesVersion: 'pp.rules_version',
  error: 'pp.error',
} as const;

export const OTEL_EVENT_NAME = 'prompt-protection.decision';
export const OTEL_COUNTER_NAME = 'pp.decisions';

type AttrValue = string | number | boolean | string[];
export type OtelAttributes = Record<string, AttrValue>;

/** The slice of `@opentelemetry/api` this bridge touches, typed structurally so the peer stays optional. */
export interface OtelApiLike {
  trace: {
    getActiveSpan?: () => OtelSpanLike | undefined;
    getTracer: (name: string, version?: string) => OtelTracerLike;
  };
  metrics?: {
    getMeter: (name: string, version?: string) => { createCounter: (name: string, opts?: { description?: string }) => { add: (n: number, attrs?: OtelAttributes) => void } };
  };
}
export interface OtelSpanLike {
  addEvent: (name: string, attrs?: OtelAttributes) => unknown;
  setAttributes?: (attrs: OtelAttributes) => unknown;
  setStatus?: (status: { code: number; message?: string }) => unknown;
  end?: () => void;
}
export interface OtelTracerLike {
  startSpan: (name: string, opts?: { attributes?: OtelAttributes }) => OtelSpanLike;
}

export interface OtelLoggerOptions {
  /** Pass the `@opentelemetry/api` module (or a compatible object); loaded on demand when omitted. */
  api?: OtelApiLike;
  tracerName?: string;
  /** `event-on-active` adds an event to the active span (falls back to a child span); `child-span` always starts one. */
  spanMode?: 'event-on-active' | 'child-span';
  /** Also count decisions on a `pp.decisions` counter. Default true when the api exposes `metrics`. */
  meter?: boolean;
}

/** Flattens a ProtectionEvent into OTel attributes. Never includes prompt or argument text. */
export function eventAttributes(event: ProtectionEvent): OtelAttributes {
  const attrs: OtelAttributes = {
    [OTEL_ATTR.decision]: event.action,
    [OTEL_ATTR.direction]: event.direction,
    [OTEL_ATTR.type]: event.type,
    [OTEL_ATTR.score]: event.score,
    [OTEL_ATTR.severity]: event.severity,
    [OTEL_ATTR.ruleIds]: event.ruleIds,
    [OTEL_ATTR.categories]: event.categories,
    [OTEL_ATTR.rulesVersion]: RULES_VERSION,
  };
  if (event.toolName !== undefined) attrs[OTEL_ATTR.toolName] = event.toolName;
  if (event.toolCallId !== undefined) attrs[OTEL_ATTR.toolCallId] = event.toolCallId;
  if (event.policy !== undefined) attrs[OTEL_ATTR.policy] = event.policy;
  if (event.reasons !== undefined) attrs[OTEL_ATTR.reasons] = event.reasons;
  if (event.sink !== undefined) attrs[OTEL_ATTR.sink] = event.sink;
  if (event.flows !== undefined) {
    attrs[OTEL_ATTR.flows] = event.flows.map((f) => `${f.kind}:${f.sourceTool}:${f.path}`);
    attrs[OTEL_ATTR.flowKinds] = [...new Set(event.flows.map((f) => f.kind))];
  }
  if (event.error !== undefined) attrs[OTEL_ATTR.error] = event.error;
  return attrs;
}

/**
 * A `ProtectionLogger` that records each decision as an OpenTelemetry span event
 * (or child span) and a counter increment. Zero-dependency core; the api module
 * is an optional peer resolved at call time.
 */
export async function createOtelLogger(options: OtelLoggerOptions = {}): Promise<ProtectionLogger> {
  const api = options.api ?? (await loadApi());
  const tracer = api.trace.getTracer(options.tracerName ?? 'prompt-protection');
  const spanMode = options.spanMode ?? 'event-on-active';
  const useMeter = options.meter ?? api.metrics !== undefined;
  const counter = useMeter && api.metrics ? api.metrics.getMeter('prompt-protection').createCounter(OTEL_COUNTER_NAME, { description: 'prompt-protection decisions by action and direction' }) : null;

  return {
    log(event: ProtectionEvent): void {
      const attrs = eventAttributes(event);
      const active = spanMode === 'event-on-active' ? api.trace.getActiveSpan?.() : undefined;
      if (active) {
        active.addEvent(OTEL_EVENT_NAME, attrs);
      } else {
        const span = tracer.startSpan(OTEL_EVENT_NAME, { attributes: attrs });
        if (event.action === 'block' && span.setStatus) span.setStatus({ code: 2, message: event.policy ?? event.type });
        span.end?.();
      }
      counter?.add(1, { [OTEL_ATTR.decision]: event.action, [OTEL_ATTR.direction]: event.direction });
    },
  };
}

async function loadApi(): Promise<OtelApiLike> {
  const specifier = '@opentelemetry/api'; // variable keeps tsc from requiring the peer's types
  return (await import(specifier)) as OtelApiLike;
}
