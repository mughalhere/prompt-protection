import { normalize } from '../normalizer.js';
import { decodeObfuscation } from '../utils/encoding.js';
import { extractIdentifiers } from '../utils/identifiers.js';
import type { IdentifierKind } from '../utils/identifiers.js';
import { normalizeUnicode } from '../utils/unicode.js';
import { buildShingles, containment, WORD_SHINGLE } from '../utils/shingle.js';
import type { ShingleSet } from '../utils/shingle.js';
import type { Flow, TaintedSource } from './types.js';

export const MIN_EXACT_CHARS = 12;
/** Leaf must yield ≥3 word shingles before word containment is trusted. */
export const MIN_CONTENT_WORDS = WORD_SHINGLE + 2;
/** Leaf must be this long before the char-shingle fallback applies. */
export const MIN_CONTENT_CHARS = 32;
export const IDENTIFIER_STRENGTH = 0.9;
/** Shortest destination-key value (e.g. a chat user id) that can flow verbatim. */
export const MIN_DESTINATION_CHARS = 4;

/** Identifier kinds that name where data goes. */
export const DESTINATION_KINDS: ReadonlySet<IdentifierKind | 'handle'> = new Set([
  'url', 'host', 'email', 'ipv4', 'phone', 'handle',
]);

/** Argument keys whose value names a recipient, endpoint or account. */
export const DESTINATION_KEYS: ReadonlySet<string> = new Set([
  'to', 'cc', 'bcc', 'recipient', 'recipients', 'user', 'userid', 'channel', 'address',
  'email', 'url', 'endpoint', 'host', 'hostname', 'target', 'destination', 'dest', 'iban',
  'account', 'accountid', 'payee', 'payeeurl', 'phone', 'number', 'processor', 'webhook',
]);

const DEFANG_RE = /\bh(?:xx|XX)ps?(?=:\/\/)|\[\.\]|\(\.\)|\s\(?dot\)?\s(?=[a-z0-9-]+(?:\s|$|[/?#]))/gi;

/** Undoes common URL defanging (`hxxps://`, `evil[.]com`, `evil (dot) com`). */
export function defang(text: string): string {
  return text.replace(DEFANG_RE, (m) => (m.toLowerCase().startsWith('hxx') ? m.replace(/xx/i, 'tt') : '.'));
}

/** Decoded (percent/base64) text without homoglyph folding, so digits survive. */
function decodedText(text: string): string {
  return decodeObfuscation(normalizeUnicode(text));
}

function keyOf(path: string): string {
  const tail = path.slice(path.lastIndexOf('.') + 1).replace(/\[\d+\]$/, '');
  return tail.toLowerCase().replace(/[^a-z]/g, '');
}

export interface ArgLeaf {
  path: string;
  value: string;
}

/** Deep-walks an argument object collecting every string leaf and object key. */
export function collectLeaves(args: unknown, path = 'args', out: ArgLeaf[] = [], depth = 0): ArgLeaf[] {
  if (depth > 32) return out;
  if (typeof args === 'string') {
    out.push({ path, value: args });
  } else if (Array.isArray(args)) {
    args.forEach((item, i) => collectLeaves(item, `${path}[${i}]`, out, depth + 1));
  } else if (args !== null && typeof args === 'object') {
    for (const key of Object.keys(args)) {
      out.push({ path: `${path}.${key}`, value: key });
      collectLeaves((args as Record<string, unknown>)[key], `${path}.${key}`, out, depth + 1);
    }
  }
  return out;
}

/** Stringifies a tool result for scanning; objects become compact JSON. */
export function stringifyValue(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === undefined || value === null) return '';
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value);
  }
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return String(value);
  }
}

/** Lowercased identifier values (→ kind) from the raw, defanged and decoded forms of `text`. */
export function identifierValues(text: string): Map<string, IdentifierKind> {
  const out = new Map<string, IdentifierKind>();
  const defanged = defang(text);
  const variants = defanged === text ? [text, decodedText(text)] : [text, defanged, decodedText(defanged)];
  for (const variant of variants) {
    for (const id of extractIdentifiers(variant)) {
      const value = id.value.toLowerCase();
      if (!out.has(value)) out.set(value, id.kind);
    }
  }
  return out;
}

export interface IndexedSource extends TaintedSource {
  /** Kept for eviction so postings can be removed without a rebuild. */
  wordHashes: Set<number>;
  charHashes: Set<number>;
}

/**
 * Inverted index over every registered source: shingle hash → source ids and
 * identifier → source ids. Lookup cost is per needle shingle, not per source.
 */
export class SourceIndex {
  private readonly words = new Map<number, Set<string>>();
  private readonly chars = new Map<number, Set<string>>();
  private readonly ids = new Map<string, Set<string>>();
  private readonly byId = new Map<string, IndexedSource>();
  private readonly order: IndexedSource[] = [];
  private totalChars = 0;

  constructor(
    private readonly maxSources: number,
    private readonly maxSourceChars: number,
  ) {}

  get sources(): readonly IndexedSource[] {
    return this.order;
  }

  get(id: string): IndexedSource | undefined {
    return this.byId.get(id);
  }

  has(id: string): boolean {
    return this.byId.has(id);
  }

  add(source: TaintedSource): IndexedSource {
    const indexed: IndexedSource = {
      ...source,
      wordHashes: source.shingles.words,
      charHashes: source.shingles.chars,
    };
    this.order.push(indexed);
    this.byId.set(indexed.id, indexed);
    this.totalChars += indexed.text.length;
    for (const h of indexed.wordHashes) post(this.words, h, indexed.id);
    for (const h of indexed.charHashes) post(this.chars, h, indexed.id);
    for (const v of indexed.identifiers.keys()) post(this.ids, v, indexed.id);
    this.evict();
    return indexed;
  }

  clear(): void {
    this.words.clear();
    this.chars.clear();
    this.ids.clear();
    this.byId.clear();
    this.order.length = 0;
    this.totalChars = 0;
  }

  private evict(): void {
    while (
      this.order.length > 0 &&
      (this.order.length > this.maxSources || this.totalChars > this.maxSourceChars)
    ) {
      const victim = this.order.shift() as IndexedSource;
      this.byId.delete(victim.id);
      this.totalChars -= victim.text.length;
      for (const h of victim.wordHashes) unpost(this.words, h, victim.id);
      for (const h of victim.charHashes) unpost(this.chars, h, victim.id);
      for (const v of victim.identifiers.keys()) unpost(this.ids, v, victim.id);
    }
  }

  /** Sources sharing at least one identifier with `values`, keyed by matched value. */
  identifierHits(values: Iterable<string>): Map<string, Set<string>> {
    const out = new Map<string, Set<string>>();
    for (const v of values) {
      const hit = this.ids.get(v);
      if (hit !== undefined && hit.size > 0) out.set(v, hit);
    }
    return out;
  }

  /** Per-source containment of `needle` computed through the posting lists. */
  containment(needle: ShingleSet): Map<string, { word: number; char: number }> {
    const wordHits = countHits(this.words, needle.words);
    const charHits = countHits(this.chars, needle.chars);
    const out = new Map<string, { word: number; char: number }>();
    for (const [id, hits] of wordHits) {
      out.set(id, { word: hits / needle.words.size, char: 0 });
    }
    for (const [id, hits] of charHits) {
      const entry = out.get(id) ?? { word: 0, char: 0 };
      entry.char = hits / needle.chars.size;
      out.set(id, entry);
    }
    return out;
  }
}

function post(map: Map<number | string, Set<string>>, key: number | string, id: string): void {
  const set = map.get(key);
  if (set === undefined) map.set(key, new Set([id]));
  else set.add(id);
}

function unpost(map: Map<number | string, Set<string>>, key: number | string, id: string): void {
  const set = map.get(key);
  if (set === undefined) return;
  set.delete(id);
  if (set.size === 0) map.delete(key);
}

function countHits(map: Map<number, Set<string>>, needle: Set<number>): Map<string, number> {
  const hits = new Map<string, number>();
  for (const h of needle) {
    const ids = map.get(h);
    if (ids === undefined) continue;
    for (const id of ids) hits.set(id, (hits.get(id) ?? 0) + 1);
  }
  return hits;
}

export interface FlowThresholds {
  minContainment: number;
  minCharContainment: number;
}

export interface TrustState {
  /** Lowercased identifier values the user authored. */
  identifiers: Set<string>;
  /** Normalized user text; leaves contained in it are user-authored. */
  text: string;
}

export interface FlowReport {
  flows: Flow[];
  /** Leaves the user did not author verbatim; the only ones worth scanning. */
  untrustedLeaves: ArgLeaf[];
  /** True when the call names ≥1 destination and every one is user-authored. */
  destinationTrusted: boolean;
}

function isTrusted(value: string, trust: TrustState): boolean {
  return trust.identifiers.has(value) || (trust.text.length > 0 && trust.text.includes(value));
}

function preview(s: string): string {
  return s.length <= 64 ? s : `${s.slice(0, 61)}…`;
}

/**
 * Runs the flow detectors on every string leaf of `args`. A leaf that appears
 * verbatim in trusted user text never produces a flow; a destination-key leaf
 * (`to`, `url`, `user`…) flows when its value appears verbatim in any source.
 */
export function detectFlows(
  leaves: readonly ArgLeaf[],
  index: SourceIndex,
  trust: TrustState,
  thresholds: FlowThresholds,
): FlowReport {
  const flows: Flow[] = [];
  const untrustedLeaves: ArgLeaf[] = [];
  let destinations = 0;
  let trustedDestinations = 0;

  for (const leaf of leaves) {
    const { normalized } = normalize(leaf.value);
    const compact = normalized.trim();
    if (compact.length === 0) continue;
    const userAuthored = trust.text.length > 0 && trust.text.includes(compact);
    if (!userAuthored) untrustedLeaves.push(leaf);

    const ids = identifierValues(leaf.value);
    const destinationKey = DESTINATION_KEYS.has(keyOf(leaf.path));
    for (const [value, kind] of ids) {
      if (!DESTINATION_KINDS.has(kind)) continue;
      destinations++;
      if (isTrusted(value, trust)) trustedDestinations++;
    }
    if (destinationKey && ids.size === 0 && compact.length >= MIN_DESTINATION_CHARS) {
      destinations++;
      if (userAuthored || isTrusted(compact, trust)) trustedDestinations++;
    }
    if (index.sources.length === 0) continue;

    for (const [value, sourceIds] of index.identifierHits(ids.keys())) {
      if (isTrusted(value, trust)) continue;
      const kind = ids.get(value) as IdentifierKind;
      for (const sourceId of sourceIds) {
        const src = index.get(sourceId);
        if (src === undefined) continue;
        flows.push({
          kind: 'identifier',
          identifierKind: kind,
          sourceId,
          sourceTool: src.tool,
          path: leaf.path,
          value,
          strength: IDENTIFIER_STRENGTH,
        });
      }
    }

    if (userAuthored) continue;

    if (destinationKey && ids.size === 0 && compact.length >= MIN_DESTINATION_CHARS && !isTrusted(compact, trust)) {
      for (const src of index.sources) {
        if (!src.normalized.includes(compact)) continue;
        flows.push({
          kind: 'identifier',
          identifierKind: 'handle',
          sourceId: src.id,
          sourceTool: src.tool,
          path: leaf.path,
          value: compact,
          strength: IDENTIFIER_STRENGTH,
        });
      }
    }

    const needle = buildShingles(compact);
    const scores = index.containment(needle);
    const wordEligible = needle.wordCount >= MIN_CONTENT_WORDS;
    const charEligible = compact.length >= MIN_CONTENT_CHARS;

    for (const [sourceId, score] of scores) {
      const src = index.get(sourceId);
      if (src === undefined) continue;
      if (compact.length >= MIN_EXACT_CHARS && score.char >= 1 && src.normalized.includes(compact)) {
        flows.push({
          kind: 'exact',
          sourceId,
          sourceTool: src.tool,
          path: leaf.path,
          value: preview(compact),
          strength: 1,
        });
        continue;
      }
      const wordFlow = wordEligible && score.word >= thresholds.minContainment;
      const charFlow = charEligible && score.char >= thresholds.minCharContainment;
      if (wordFlow || charFlow) {
        flows.push({
          kind: 'content',
          sourceId,
          sourceTool: src.tool,
          path: leaf.path,
          value: preview(compact),
          strength: Math.max(wordFlow ? score.word : 0, charFlow ? score.char : 0),
        });
      }
    }
  }

  return {
    flows,
    untrustedLeaves,
    destinationTrusted: destinations > 0 && trustedDestinations === destinations,
  };
}

/** Word/char containment of `needle` in `hay` (exported for tests and tuning). */
export function containmentOf(needle: string, hay: string): { word: number; char: number } {
  const c = containment(normalize(needle).normalized, normalize(hay).normalized);
  return { word: c.word, char: c.char };
}
