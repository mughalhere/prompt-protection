import {
  createNonceStore,
  EnvelopeError,
  exportPublicKey,
  fromBase64Url,
  generateKey,
  importPublicKey,
  isEnvelope,
  open,
  seal,
  toBase64Url,
} from '../../src/envelope/index';
import type { Envelope, EnvelopeKey } from '../../src/envelope/index';

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    return err instanceof EnvelopeError ? err.code : `other:${String(err)}`;
  }
  return 'ok';
}

const HS: EnvelopeKey = { alg: 'HS256', secret: 'a-shared-secret-of-reasonable-length', kid: 'k1' };

describe('envelope seal / open (HS256)', () => {
  it('round-trips a payload with its label, iat, nonce and exp', async () => {
    const env = await seal({ text: 'hello', n: 1 }, HS, { label: 'tool', ttlMs: 60_000, from: 'agent-a', now: () => 1_000 });
    expect(env).toMatchObject({ v: 1, alg: 'HS256', kid: 'k1', iat: 1_000, exp: 61_000, label: 'tool', from: 'agent-a', payload: { text: 'hello', n: 1 } });
    expect(env.nonce).toHaveLength(32);
    expect(env.sig).toMatch(/^[A-Za-z0-9_-]+$/);
    const opened = await open<{ text: string }>(JSON.parse(JSON.stringify(env)), HS, { now: () => 2_000 });
    expect(opened.payload.text).toBe('hello');
    expect(isEnvelope(env)).toBe(true);
  });

  it('rejects a tampered payload, label or signature (bad-signature)', async () => {
    const env = await seal({ secret: 1 }, HS, { label: 'tool' });
    expect(await codeOf(open({ ...env, payload: { secret: 2 } }, HS))).toBe('bad-signature');
    expect(await codeOf(open({ ...env, label: 'system' }, HS))).toBe('bad-signature');
    expect(await codeOf(open({ ...env, sig: toBase64Url(new Uint8Array(32)) }, HS))).toBe('bad-signature');
    expect(await codeOf(open({ ...env, sig: '***' }, HS))).toBe('bad-signature');
    expect(await codeOf(open(env, { alg: 'HS256', secret: 'another-secret', kid: 'k1' }))).toBe('bad-signature');
  });

  it('reports malformed, unknown-kid, expired (exp, skew, requireExp) and replayed, in that order', async () => {
    expect(await codeOf(open({ v: 2 }, HS))).toBe('malformed');
    expect(await codeOf(open('nope', HS))).toBe('malformed');
    const env = await seal({ a: 1 }, HS, { ttlMs: 1_000, now: () => 10_000 });
    expect(await codeOf(open(env, { alg: 'HS256', secret: HS.alg === 'HS256' ? HS.secret : '', kid: 'k2' }))).toBe('unknown-kid');
    expect(await codeOf(open(env, [{ alg: 'EdDSA', publicKey: {} as CryptoKey, kid: 'k1' }]))).toBe('unknown-kid');
    expect(await codeOf(open(env, HS, { now: () => 12_000 }))).toBe('expired');
    expect(await codeOf(open(env, HS, { now: () => 5_000, maxSkewMs: 1_000 }))).toBe('expired');
    expect(await codeOf(open(env, HS, { now: () => 9_500 }))).toBe('ok');
    expect(await codeOf(open(env, HS, { now: () => 9_950 }))).toBe('ok');
    const noExp = await seal({ a: 1 }, HS, { now: () => 10_000 });
    expect(await codeOf(open(noExp, HS, { now: () => 10_000, requireExp: true }))).toBe('expired');
    const nonces = createNonceStore(2);
    expect(await codeOf(open(env, HS, { now: () => 10_500, nonces }))).toBe('ok');
    expect(await codeOf(open(env, HS, { now: () => 10_500, nonces }))).toBe('replayed');
    // A forged envelope never reaches the nonce store.
    const forged = { ...env, payload: { a: 2 }, nonce: 'forged-nonce' };
    expect(await codeOf(open(forged, HS, { now: () => 10_500, nonces }))).toBe('bad-signature');
    expect(nonces.has('forged-nonce')).toBe(false);
    nonces.add('x');
    nonces.add('y');
    expect(nonces.size).toBe(2);
  });

  it('selects a key by kid among several, and a kid-less envelope only matches kid-less keys', async () => {
    const k2: EnvelopeKey = { alg: 'HS256', secret: 'second', kid: 'k2' };
    const env = await seal({ a: 1 }, k2);
    expect((await open(env, [HS, k2])).kid).toBe('k2');
    const bare: EnvelopeKey = { alg: 'HS256', secret: 'bare' };
    const bareEnv = await seal({ a: 1 }, bare);
    expect(await codeOf(open(bareEnv, [HS, k2]))).toBe('unknown-kid');
    expect(await codeOf(open(bareEnv, [HS, bare]))).toBe('ok');
  });

  it('base64url helpers round-trip and reject non-base64url input', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
    expect(fromBase64Url('not base64!')).toBeNull();
  });
});

describe('envelope (EdDSA / Ed25519)', () => {
  const available = typeof globalThis.crypto?.subtle?.generateKey === 'function';
  const run = available ? it : it.skip;

  run('signs with the private key and verifies with the exported public key only', async () => {
    const key = await generateKey('EdDSA', 'ed1');
    const env = await seal({ hello: 'world' }, key, { label: 'user' });
    expect(env.alg).toBe('EdDSA');
    const pub = await importPublicKey(await exportPublicKey(key), 'ed1');
    expect((await open(env, pub)).payload).toEqual({ hello: 'world' });
    expect(await codeOf(open({ ...env, payload: { hello: 'mars' } }, pub))).toBe('bad-signature');
    expect(await codeOf(seal({ a: 1 }, pub))).toBe('crypto-unavailable');
    const other = await generateKey('EdDSA', 'ed1');
    expect(await codeOf(open(env, other))).toBe('bad-signature');
  });

  it('fails closed with crypto-unavailable when subtle is missing', async () => {
    const saved = globalThis.crypto;
    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
    try {
      expect(await codeOf(seal({ a: 1 }, HS))).toBe('crypto-unavailable');
      expect(await codeOf(generateKey('HS256'))).toBe('crypto-unavailable');
      const env: Envelope<{ a: number }> = { v: 1, alg: 'HS256', iat: 0, nonce: 'n', label: 'tool', payload: { a: 1 }, sig: 'AA' };
      expect(await codeOf(open(env, { alg: 'HS256', secret: 's' }))).toBe('crypto-unavailable');
    } finally {
      Object.defineProperty(globalThis, 'crypto', { value: saved, configurable: true });
    }
  });
});
