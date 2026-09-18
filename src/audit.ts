/**
 * @packageDocumentation
 * @beta Preview tier: may change in a minor release. See docs/API_STABILITY.md.
 */
import { RULES_VERSION } from './patterns/version.js';
import { digest } from './utils/digest.js';
import type { Action, FlowSummary, ProtectionEvent, ProtectionLogger, SeverityLevel, ThreatCategory } from './types.js';

export type AuditContent = { hash: string; length: number } | { preview: string; length: number } | null;

export interface AuditRecord {
  v: 1;
  seq: number;
  ts: string;
  runId?: string;
  type: ProtectionEvent['type'];
  direction: ProtectionEvent['direction'];
  action: Action;
  score: number;
  severity: SeverityLevel;
  categories: ThreatCategory[];
  ruleIds: string[];
  toolName?: string;
  toolCallId?: string;
  policy?: string;
  reasons?: string[];
  sink?: string;
  flows?: FlowSummary[];
  content: AuditContent;
  error?: string;
  rulesVersion: string;
  prevHash: string | null;
  hash: string;
}

export interface AuditLogOptions {
  /** Receives one JSON line per record. */
  sink: (line: string, record: AuditRecord) => void | Promise<void>;
  /** `hash` (default) stores a content digest; `preview` a truncated excerpt; `none` omits content entirely. */
  redact?: 'hash' | 'preview' | 'none';
  maxPreview?: number;
  runId?: string;
  clock?: () => Date;
}

export interface AuditLog extends ProtectionLogger {
  readonly seq: number;
  readonly lastHash: string | null;
  /** Resolves when every record accepted so far has been hashed and written. */
  flush(): Promise<void>;
}

/**
 * Tamper-evident, replayable JSONL audit log usable as the `logger` option of
 * `analyzePrompt`, `analyzeOutput` and `createGuard`. Records form a SHA-256
 * hash chain; raw content is stored only as a digest unless `redact: 'preview'`.
 */
export function createAuditLog(options: AuditLogOptions): AuditLog {
  const redact = options.redact ?? 'hash';
  const maxPreview = options.maxPreview ?? 200;
  const clock = options.clock ?? (() => new Date());
  let seq = 0;
  let lastHash: string | null = null;
  let chain: Promise<void> = Promise.resolve();

  async function write(event: ProtectionEvent, content: string): Promise<void> {
    let body: AuditContent = null;
    if (redact === 'hash') body = { hash: await digest(content), length: content.length };
    else if (redact === 'preview') body = { preview: content.length > maxPreview ? `${content.slice(0, maxPreview)}…` : content, length: content.length };
    seq += 1;
    const unsigned: Omit<AuditRecord, 'hash'> = {
      v: 1,
      seq,
      ts: clock().toISOString(),
      ...(options.runId !== undefined ? { runId: options.runId } : {}),
      type: event.type,
      direction: event.direction,
      action: event.action,
      score: event.score,
      severity: event.severity,
      categories: event.categories,
      ruleIds: event.ruleIds,
      ...(event.toolName !== undefined ? { toolName: event.toolName } : {}),
      ...(event.toolCallId !== undefined ? { toolCallId: event.toolCallId } : {}),
      ...(event.policy !== undefined ? { policy: event.policy } : {}),
      ...(event.reasons !== undefined ? { reasons: event.reasons } : {}),
      ...(event.sink !== undefined ? { sink: event.sink } : {}),
      ...(event.flows !== undefined ? { flows: event.flows } : {}),
      content: body,
      ...(event.error !== undefined ? { error: event.error } : {}),
      rulesVersion: RULES_VERSION,
      prevHash: lastHash,
    };
    const hash = await digest(unsigned);
    const record: AuditRecord = { ...unsigned, hash };
    lastHash = hash;
    await options.sink(JSON.stringify(record), record);
  }

  const enqueue = (event: ProtectionEvent, content: string): Promise<void> => {
    chain = chain.then(() => write(event, content));
    return chain;
  };

  return {
    log: (event) => enqueue(event, ''),
    logWithContent: (event, content) => enqueue(event, content),
    flush: () => chain,
    get seq() {
      return seq;
    },
    get lastHash() {
      return lastHash;
    },
  };
}

export interface ReplayResult {
  records: AuditRecord[];
  valid: boolean;
  /** `seq` of the first record whose hash or chain link does not verify. */
  brokenAt?: number;
}

/** Re-verifies every record's hash and its link to the previous one. */
export async function replayAuditLog(jsonl: string | Iterable<string>): Promise<ReplayResult> {
  const lines = typeof jsonl === 'string' ? jsonl.split('\n') : [...jsonl];
  const records: AuditRecord[] = [];
  let prev: string | null = null;
  for (const line of lines) {
    if (line.trim().length === 0) continue;
    const record = JSON.parse(line) as AuditRecord;
    records.push(record);
    const { hash, ...unsigned } = record;
    const expected = await digest(unsigned);
    if (hash !== expected || record.prevHash !== prev) return { records, valid: false, brokenAt: record.seq };
    prev = hash;
  }
  return { records, valid: true };
}
