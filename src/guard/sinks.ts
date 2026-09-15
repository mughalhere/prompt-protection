import type { SinkKind, SinkResolver } from './types.js';

export interface SinkPattern {
  sink: SinkKind;
  pattern: RegExp;
}

/**
 * Ordered tool-name heuristics. Read-only verbs are matched first so
 * `fetch_url` / `get_record` stay `none`; a bare `send` falls to `network`.
 */
export const DEFAULT_SINK_PATTERNS: readonly SinkPattern[] = [
  { sink: 'none', pattern: /^(?:get|read|fetch|list|search|query|lookup|find|view|browse|load|open|reply_to_user|final_answer|respond|answer)(?:_|$)/i },
  { sink: 'network', pattern: /http|curl|webhook|socket|dns/i },
  { sink: 'payment', pattern: /pay|payment|charge|transfer|checkout|purchase|refund|billing|invoice|wire|donat/i },
  { sink: 'exec', pattern: /exec|shell|bash|command|cmd|terminal|spawn|eval|script|run(?:_|$)|sudo|process/i },
  { sink: 'email', pattern: /e?mail|smtp|gmail|outlook/i },
  { sink: 'message', pattern: /slack|discord|teams|sms|whatsapp|telegram|signal|imessage|message|msg|chat|dm(?:_|$)|comment|tweet|post(?:_|$)|publish|notify|notification|broadcast/i },
  { sink: 'file-write', pattern: /write|save|create|delete|remove|append|upload|edit|update|move|rename|mkdir|rm(?:_|$)|unlink|put_file|store|persist/i },
  { sink: 'network', pattern: /http|url|request|curl|webhook|api|send|submit|call|dispatch|push|sync|export|download|navigate|visit|connect|socket|dns/i },
];

/** Classifies a tool name with the default heuristics. Unknown names are `none`. */
export function defaultSink(toolName: string): SinkKind {
  for (const entry of DEFAULT_SINK_PATTERNS) {
    if (entry.pattern.test(toolName)) return entry.sink;
  }
  return 'none';
}

/** Builds a resolver from the `sinks` option; explicit entries win, defaults fill gaps. */
export function createSinkResolver(
  sinks: Record<string, SinkKind> | SinkResolver | undefined,
): (toolName: string) => SinkKind {
  if (typeof sinks === 'function') {
    return (name) => sinks(name) ?? defaultSink(name);
  }
  const map = sinks ?? {};
  return (name) => {
    const explicit = Object.prototype.hasOwnProperty.call(map, name) ? map[name] : undefined;
    return explicit ?? defaultSink(name);
  };
}

/** Sinks where untrusted data leaving the process is the concern. */
export const EXFIL_SINKS: ReadonlySet<SinkKind> = new Set(['network', 'email', 'message']);
/** Sinks where untrusted data can change local state or run code. */
export const EXEC_SINKS: ReadonlySet<SinkKind> = new Set(['exec', 'file-write']);
