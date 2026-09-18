import { canonicalJson, CanonicalJsonError, digest, digestSyncWeak, fnv1a64Hex } from '../../src/utils/canonical';

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (err) {
    return err instanceof CanonicalJsonError ? err.code : `other:${String(err)}`;
  }
  return undefined;
}

describe('canonicalJson (RFC 8785 subset)', () => {
  it('sorts object keys by UTF-16 code unit, recursively', () => {
    expect(canonicalJson({ b: 1, a: [{ d: 1, c: 2 }] })).toBe('{"a":[{"c":2,"d":1}],"b":1}');
    // RFC 8785 §3.2.3: "€" (0x20AC) sorts before "😀" (surrogates 0xD83D…), both after "a".
    expect(canonicalJson({ '😀': 1, '€': 2, a: 3 })).toBe('{"a":3,"€":2,"😀":1}');
    expect(canonicalJson({ '10': 1, '9': 2, 'A': 3, 'a': 4 })).toBe('{"10":1,"9":2,"A":3,"a":4}');
  });

  it('serialises numbers with the ES algorithm and folds -0', () => {
    expect(canonicalJson({ a: 1e21, b: 1e-7, c: 0.1, d: -0, e: 100 })).toBe('{"a":1e+21,"b":1e-7,"c":0.1,"d":0,"e":100}');
  });

  it('honours toJSON before sorting (Date → ISO string)', () => {
    expect(canonicalJson({ t: new Date(0) })).toBe('{"t":"1970-01-01T00:00:00.000Z"}');
    const custom = { toJSON: () => ({ z: 1, y: 2 }) };
    expect(canonicalJson(custom)).toBe('{"y":2,"z":1}');
  });

  it('omits undefined members and nulls undefined array items', () => {
    expect(canonicalJson({ a: undefined, b: 1, c: () => 1 })).toBe('{"b":1}');
    expect(canonicalJson([1, undefined, 3])).toBe('[1,null,3]');
  });

  it('escapes strings exactly as JSON.stringify', () => {
    expect(canonicalJson('a"b\\c\n')).toBe(JSON.stringify('a"b\\c\n'));
  });

  it('fails closed on values JSON cannot represent', () => {
    expect(codeOf(() => canonicalJson({ a: NaN }))).toBe('non-finite');
    expect(codeOf(() => canonicalJson([Infinity]))).toBe('non-finite');
    expect(codeOf(() => canonicalJson({ n: 10n }))).toBe('bigint');
    expect(codeOf(() => canonicalJson(new Map([['a', 1]])))).toBe('unsupported');
    expect(codeOf(() => canonicalJson(new Set([1])))).toBe('unsupported');
    expect(codeOf(() => canonicalJson(undefined))).toBe('unsupported');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(codeOf(() => canonicalJson(cyclic))).toBe('cycle');
    let deep: unknown = 1;
    for (let i = 0; i < 66; i++) deep = [deep];
    expect(codeOf(() => canonicalJson(deep))).toBe('depth');
  });

  it('does not treat a shared (non-cyclic) reference as a cycle', () => {
    const shared = { x: 1 };
    expect(canonicalJson({ a: shared, b: shared })).toBe('{"a":{"x":1},"b":{"x":1}}');
  });

  it('so {a:NaN} and {a:null} can no longer collide', () => {
    expect(canonicalJson({ a: null })).toBe('{"a":null}');
    expect(codeOf(() => canonicalJson({ a: NaN }))).toBe('non-finite');
  });
});

describe('digests', () => {
  it('fnv1a64Hex matches the reference offset basis and is stable', () => {
    expect(fnv1a64Hex('')).toBe('cbf29ce484222325');
    expect(fnv1a64Hex('a')).toBe('af63dc4c8601ec8c');
  });

  it('digest hashes strings raw and objects through canonicalJson, labelled by algorithm', async () => {
    const viaObject = await digest({ b: 1, a: 2 });
    const viaString = await digest('{"a":2,"b":1}');
    expect(viaObject).toBe(viaString);
    expect(viaObject).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('digestSyncWeak is the labelled fnv1a64 of the canonical form', () => {
    expect(digestSyncWeak({ b: 1, a: 2 })).toBe(`fnv1a64:${fnv1a64Hex('{"a":2,"b":1}')}`);
    expect(digestSyncWeak('x')).toBe(`fnv1a64:${fnv1a64Hex('x')}`);
  });

  it('digest rejects what canonicalJson rejects', async () => {
    await expect(digest({ a: NaN })).rejects.toBeInstanceOf(CanonicalJsonError);
  });
});
