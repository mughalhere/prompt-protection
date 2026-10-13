/**
 * @packageDocumentation
 * @beta Preview tier: may change in a minor release. See docs/API_STABILITY.md.
 */
// Signed taint envelopes: carry a value and its provenance label across a process boundary so the
// receiving guard can trust the label only if the signature, expiry and nonce check out. HMAC-SHA-256
// everywhere; Ed25519 where WebCrypto has it (Node ≥ 20.19.3 / 22.13). No non-cryptographic fallback:
// below the floor `open()` fails closed with `crypto-unavailable`.
import { canonicalJson } from '../utils/canonical.js';
import { randomHex } from '../utils/random.js';
import type { TrustLabel } from '../guard/memory.js';

export type EnvelopeAlg = 'HS256' | 'EdDSA';

export type EnvelopeKey =
  | { alg: 'HS256'; secret: Uint8Array | string; kid?: string }
  | { alg: 'EdDSA'; publicKey: CryptoKey; privateKey?: CryptoKey; kid?: string };

export interface Envelope<T> {
  v: 1;
  alg: EnvelopeAlg;
  kid?: string;
  /** Issued-at, ms since epoch. */
  iat: number;
  /** Expiry, ms since epoch. */
  exp?: number;
  nonce: string;
  label: TrustLabel;
  /** Producer id, becomes the lineage edge on the receiving side. */
  from?: string;
  payload: T;
  /** base64url signature over `canonicalJson` of every other field. */
  sig: string;
}

export type EnvelopeErrorCode = 'bad-signature' | 'expired' | 'replayed' | 'unknown-kid' | 'crypto-unavailable' | 'malformed';

export class EnvelopeError extends Error {
  readonly code: EnvelopeErrorCode;
  constructor(code: EnvelopeErrorCode, message: string) {
    super(message);
    this.name = 'EnvelopeError';
    this.code = code;
  }
}

export interface NonceStore {
  has(nonce: string): boolean;
  add(nonce: string): void;
  readonly size: number;
}

/** In-memory ring of seen nonces; the oldest is dropped past `max`. */
export function createNonceStore(max = 1024): NonceStore {
  const seen = new Set<string>();
  return {
    has: (n) => seen.has(n),
    add(n) {
      seen.add(n);
      if (seen.size > max) seen.delete(seen.values().next().value as string);
    },
    get size() {
      return seen.size;
    },
  };
}

export interface SealOptions {
  label?: TrustLabel;
  ttlMs?: number;
  from?: string;
  now?: () => number;
}

export interface OpenOptions {
  now?: () => number;
  /** How far in the future `iat` may sit before the envelope is rejected. Default 60 000. */
  maxSkewMs?: number;
  /** Replay protection; without a store nonces are not checked. */
  nonces?: NonceStore;
  /** Reject envelopes that carry no `exp`. Default false. */
  requireExp?: boolean;
}

const DEFAULT_MAX_SKEW_MS = 60_000;
const encoder = new TextEncoder();

function subtleOrThrow(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) throw new EnvelopeError('crypto-unavailable', 'WebCrypto subtle is not available');
  return subtle;
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i] as number);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  try {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function secretBytes(secret: Uint8Array | string): Uint8Array {
  return typeof secret === 'string' ? encoder.encode(secret) : secret;
}

async function hmacKey(secret: Uint8Array | string, usage: KeyUsage): Promise<CryptoKey> {
  const subtle = subtleOrThrow();
  try {
    return await subtle.importKey('raw', secretBytes(secret) as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, [usage]);
  } catch (err) {
    throw new EnvelopeError('crypto-unavailable', `HMAC import failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function unsigned<T>(env: Envelope<T>): string {
  const rest: Omit<Envelope<T>, 'sig'> & { sig?: string } = { ...env };
  delete rest.sig;
  return canonicalJson(rest);
}

async function sign(text: string, key: EnvelopeKey): Promise<string> {
  const subtle = subtleOrThrow();
  const data = encoder.encode(text);
  try {
    if (key.alg === 'HS256') {
      const k = await hmacKey(key.secret, 'sign');
      return toBase64Url(new Uint8Array(await subtle.sign('HMAC', k, data)));
    }
    if (key.privateKey === undefined) throw new EnvelopeError('crypto-unavailable', 'EdDSA key has no privateKey');
    return toBase64Url(new Uint8Array(await subtle.sign({ name: 'Ed25519' }, key.privateKey, data)));
  } catch (err) {
    if (err instanceof EnvelopeError) throw err;
    throw new EnvelopeError('crypto-unavailable', `sign failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function verify(text: string, sig: string, key: EnvelopeKey): Promise<boolean> {
  const subtle = subtleOrThrow();
  const bytes = fromBase64Url(sig);
  if (bytes === null) return false;
  const data = encoder.encode(text);
  try {
    if (key.alg === 'HS256') {
      const k = await hmacKey(key.secret, 'verify');
      return await subtle.verify('HMAC', k, bytes as BufferSource, data);
    }
    return await subtle.verify({ name: 'Ed25519' }, key.publicKey, bytes as BufferSource, data);
  } catch (err) {
    if (err instanceof EnvelopeError) throw err;
    throw new EnvelopeError('crypto-unavailable', `verify failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export function isEnvelope(v: unknown): v is Envelope<unknown> {
  if (!isRecord(v) || v.v !== 1) return false;
  if (v.alg !== 'HS256' && v.alg !== 'EdDSA') return false;
  if (typeof v.iat !== 'number' || !Number.isFinite(v.iat)) return false;
  if (v.exp !== undefined && (typeof v.exp !== 'number' || !Number.isFinite(v.exp))) return false;
  if (v.kid !== undefined && typeof v.kid !== 'string') return false;
  if (v.from !== undefined && typeof v.from !== 'string') return false;
  return typeof v.nonce === 'string' && typeof v.label === 'string' && typeof v.sig === 'string' && 'payload' in v;
}

/** Seals `payload` with its provenance label. Throws `EnvelopeError('crypto-unavailable')` below the crypto floor. */
export async function seal<T>(payload: T, key: EnvelopeKey, options: SealOptions = {}): Promise<Envelope<T>> {
  subtleOrThrow();
  const now = options.now ?? Date.now;
  const iat = now();
  const env: Envelope<T> = {
    v: 1,
    alg: key.alg,
    ...(key.kid !== undefined ? { kid: key.kid } : {}),
    iat,
    ...(options.ttlMs !== undefined ? { exp: iat + options.ttlMs } : {}),
    nonce: randomHex(32),
    label: options.label ?? 'untrusted',
    ...(options.from !== undefined ? { from: options.from } : {}),
    payload,
    sig: '',
  };
  env.sig = await sign(unsigned(env), key);
  return env;
}

function selectKey(env: Envelope<unknown>, keys: EnvelopeKey | readonly EnvelopeKey[]): EnvelopeKey {
  const list = Array.isArray(keys) ? (keys as readonly EnvelopeKey[]) : [keys as EnvelopeKey];
  const candidates = list.filter((k) => k.alg === env.alg && (env.kid === undefined ? k.kid === undefined : k.kid === env.kid));
  const key = candidates[0];
  if (key === undefined) throw new EnvelopeError('unknown-kid', `no ${env.alg} key for kid ${env.kid ?? '(none)'}`);
  return key;
}

/**
 * Verifies and returns the envelope. Order: malformed → unknown key → signature → expiry / skew →
 * nonce. Signature before nonce, so a forger cannot poison the nonce store.
 */
export async function open<T = unknown>(env: unknown, keys: EnvelopeKey | readonly EnvelopeKey[], options: OpenOptions = {}): Promise<Envelope<T>> {
  if (!isEnvelope(env)) throw new EnvelopeError('malformed', 'not a v1 envelope');
  const key = selectKey(env, keys);
  const ok = await verify(unsigned(env), env.sig, key);
  if (!ok) throw new EnvelopeError('bad-signature', 'signature does not verify');
  const now = (options.now ?? Date.now)();
  const skew = options.maxSkewMs ?? DEFAULT_MAX_SKEW_MS;
  if (env.iat > now + skew) throw new EnvelopeError('expired', 'issued in the future beyond the allowed skew');
  if (env.exp !== undefined && env.exp < now) throw new EnvelopeError('expired', 'envelope expired');
  if (options.requireExp === true && env.exp === undefined) throw new EnvelopeError('expired', 'envelope carries no exp');
  if (options.nonces !== undefined) {
    if (options.nonces.has(env.nonce)) throw new EnvelopeError('replayed', 'nonce already seen');
    options.nonces.add(env.nonce);
  }
  return env as Envelope<T>;
}

/** Generates a key: a random 32-byte HMAC secret, or an Ed25519 pair (extractable so it can be exported). */
export async function generateKey(alg: EnvelopeAlg, kid?: string): Promise<EnvelopeKey> {
  if (alg === 'HS256') {
    const secret = new Uint8Array(32);
    const c = globalThis.crypto;
    if (c === undefined) throw new EnvelopeError('crypto-unavailable', 'WebCrypto is not available');
    c.getRandomValues(secret);
    return { alg, secret, ...(kid !== undefined ? { kid } : {}) };
  }
  const subtle = subtleOrThrow();
  try {
    const pair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    return { alg, publicKey: pair.publicKey, privateKey: pair.privateKey, ...(kid !== undefined ? { kid } : {}) };
  } catch (err) {
    throw new EnvelopeError('crypto-unavailable', `Ed25519 is not available here: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Exports an Ed25519 public key as base64url raw bytes, for the receiving side. */
export async function exportPublicKey(key: EnvelopeKey): Promise<string> {
  if (key.alg !== 'EdDSA') throw new EnvelopeError('malformed', 'only EdDSA keys have a public key');
  const subtle = subtleOrThrow();
  return toBase64Url(new Uint8Array(await subtle.exportKey('raw', key.publicKey)));
}

/** Imports a base64url raw Ed25519 public key as a verify-only `EnvelopeKey`. */
export async function importPublicKey(raw: string, kid?: string): Promise<EnvelopeKey> {
  const subtle = subtleOrThrow();
  const bytes = fromBase64Url(raw);
  if (bytes === null) throw new EnvelopeError('malformed', 'public key is not base64url');
  try {
    const publicKey = await subtle.importKey('raw', bytes as BufferSource, { name: 'Ed25519' }, true, ['verify']);
    return { alg: 'EdDSA', publicKey, ...(kid !== undefined ? { kid } : {}) };
  } catch (err) {
    throw new EnvelopeError('crypto-unavailable', `Ed25519 import failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}
