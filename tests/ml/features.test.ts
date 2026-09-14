import { featurize, DEFAULT_MAX_CHARS } from '../../src/ml/features';
import { bucketOf } from '../../src/ml/hash';
import type { GramFamily } from '../../src/ml/types';

const key = (family: GramFamily, gram: string, buckets = 65536) => {
  const { bucket, sign } = bucketOf(family, gram, buckets);
  return bucket * 2 + (sign < 0 ? 1 : 0);
};

const keysOf = (v: ReturnType<typeof featurize>) =>
  Array.from(v.indices).map((idx, i) => idx * 2 + (v.signs[i] === -1 ? 1 : 0));

describe('featurize', () => {
  it('returns an empty vector for empty input', () => {
    const v = featurize('');
    expect(v.nnz).toBe(0);
    expect(v.indices.length).toBe(0);
    expect(v.signs.length).toBe(0);
  });

  it('hashes the expected grams for a tiny input', () => {
    const v = featurize('ab');
    const expected = [
      key('c3', ' ab'),
      key('c3', 'ab '),
      key('c4', ' ab '),
      key('w1', 'ab'),
    ].sort((a, b) => a - b);
    expect(keysOf(v)).toEqual([...new Set(expected)]);
    expect(v.nnz).toBe(new Set(expected).size);
  });

  it('adds word bigrams and 5-grams for longer input', () => {
    const v = featurize('ignore rules');
    const keys = new Set(keysOf(v));
    expect(keys.has(key('w2', 'ignore rules'))).toBe(true);
    expect(keys.has(key('c5', ' igno'))).toBe(true);
    expect(keys.has(key('c5', 'ules '))).toBe(true);
  });

  it('emits sorted, de-duplicated (bucket, sign) pairs', () => {
    const v = featurize('aaaa aaaa aaaa aaaa');
    const keys = keysOf(v);
    expect(keys).toEqual([...keys].sort((a, b) => a - b));
    expect(new Set(keys).size).toBe(keys.length);
    expect(v.nnz).toBe(keys.length);
    for (const s of v.signs) expect(s === 1 || s === -1).toBe(true);
  });

  it('respects a custom bucket count', () => {
    const v = featurize('some ordinary text here', { buckets: 16 });
    for (const i of v.indices) expect(i).toBeLessThan(16);
  });

  it('truncates to maxChars before featurizing', () => {
    const long = 'z'.repeat(DEFAULT_MAX_CHARS + 500) + ' tail';
    const a = featurize(long);
    const b = featurize('z'.repeat(DEFAULT_MAX_CHARS));
    expect(keysOf(a)).toEqual(keysOf(b));
    expect(keysOf(featurize('abc def', { maxChars: 3 }))).toEqual(keysOf(featurize('abc')));
  });
});
