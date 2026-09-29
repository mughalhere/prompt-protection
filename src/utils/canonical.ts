/**
 * Canonical JSON (RFC 8785 subset) and content digests.
 *
 * Equal values serialise to equal strings, so pinning, approvals and audit chains can compare
 * or hash them. Values JSON cannot represent faithfully fail closed instead of collapsing
 * (`NaN` → `null`, `Map` → `{}`) into collisions.
 */

export type CanonicalJsonErrorCode = 'non-finite' | 'bigint' | 'cycle' | 'depth' | 'unsupported';

export class CanonicalJsonError extends TypeError {
  readonly code: CanonicalJsonErrorCode;
  constructor(code: CanonicalJsonErrorCode, message: string) {
    super(message);
    this.name = 'CanonicalJsonError';
    this.code = code;
  }
}

const MAX_DEPTH = 64;

function hasToJson(value: object): value is { toJSON(key: string): unknown } {
  return typeof (value as { toJSON?: unknown }).toJSON === 'function';
}

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === null || proto === Object.prototype;
}

function serialize(value: unknown, key: string, depth: number, seen: Set<object>): string | undefined {
  if (value !== null && typeof value === 'object' && hasToJson(value)) value = value.toJSON(key);

  switch (typeof value) {
    case 'undefined':
    case 'function':
    case 'symbol':
      return undefined;
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return JSON.stringify(value);
    case 'bigint':
      throw new CanonicalJsonError('bigint', 'BigInt has no canonical JSON form');
    case 'number':
      if (!Number.isFinite(value)) throw new CanonicalJsonError('non-finite', `${String(value)} has no JSON form`);
      return value === 0 ? '0' : JSON.stringify(value);
    default:
      break;
  }
  if (value === null) return 'null';

  const obj = value as object;
  if (depth > MAX_DEPTH) throw new CanonicalJsonError('depth', `nesting deeper than ${MAX_DEPTH}`);
  if (seen.has(obj)) throw new CanonicalJsonError('cycle', 'circular reference');
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      const items = obj.map((item, i) => serialize(item, String(i), depth + 1, seen) ?? 'null');
      return `[${items.join(',')}]`;
    }
    if (!isPlainObject(obj)) {
      throw new CanonicalJsonError('unsupported', `${obj.constructor?.name ?? 'object'} has no toJSON`);
    }
    const record = obj as Record<string, unknown>;
    const parts: string[] = [];
    for (const k of Object.keys(record).sort()) {
      const v = serialize(record[k], k, depth + 1, seen);
      if (v !== undefined) parts.push(`${JSON.stringify(k)}:${v}`);
    }
    return `{${parts.join(',')}}`;
  } finally {
    seen.delete(obj);
  }
}

/**
 * Deterministic JSON: keys sorted by UTF-16 code unit, `toJSON` honoured, `undefined` members
 * omitted, `-0` → `0`. Throws `CanonicalJsonError` for non-finite numbers, BigInt, cycles, depth
 * over 64, and non-plain objects without `toJSON` (Map, Set, class instances).
 */
export function canonicalJson(value: unknown): string {
  const out = serialize(value, '', 0, new Set());
  if (out === undefined) throw new CanonicalJsonError('unsupported', 'value has no JSON form');
  return out;
}

/** FNV-1a 64-bit over UTF-8 bytes; the labelled fallback when WebCrypto is unavailable. */
export function fnv1a64Hex(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = 0xffffffffffffffffn;
  for (const b of bytes) {
    hash ^= BigInt(b);
    hash = (hash * prime) & mask;
  }
  return hash.toString(16).padStart(16, '0');
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');
}

function textOf(value: unknown): string {
  return typeof value === 'string' ? value : canonicalJson(value);
}

/**
 * `sha256:<hex>` via `crypto.subtle` when present, else `fnv1a64:<hex>`.
 * The prefix names the algorithm so a consumer never mistakes the fallback for SHA-256.
 * Strings hash as-is; everything else through `canonicalJson`.
 */
export async function digest(value: unknown): Promise<string> {
  const text = textOf(value);
  const subtle = globalThis.crypto?.subtle;
  if (subtle !== undefined) {
    const hash = await subtle.digest('SHA-256', new TextEncoder().encode(text));
    return `sha256:${toHex(hash)}`;
  }
  return `fnv1a64:${fnv1a64Hex(text)}`;
}

/** Synchronous, non-cryptographic `fnv1a64:<hex>` for counting and dedupe. Never an integrity check. */
export function digestSyncWeak(value: unknown): string {
  return `fnv1a64:${fnv1a64Hex(textOf(value))}`;
}
