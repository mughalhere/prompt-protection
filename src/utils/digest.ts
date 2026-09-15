/** Deterministic JSON: sorted object keys, so equal values hash equal. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
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

/**
 * `sha256:<hex>` via `crypto.subtle` when present, else `fnv1a64:<hex>`.
 * The prefix names the algorithm so a consumer never mistakes the fallback for SHA-256.
 */
export async function digest(value: unknown): Promise<string> {
  const text = typeof value === 'string' ? value : canonicalJson(value);
  const subtle = globalThis.crypto?.subtle;
  if (subtle !== undefined) {
    const hash = await subtle.digest('SHA-256', new TextEncoder().encode(text));
    return `sha256:${toHex(hash)}`;
  }
  return `fnv1a64:${fnv1a64Hex(text)}`;
}
