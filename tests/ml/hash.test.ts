import { bucketOf } from '../../src/ml/hash';
import { fnv1a32 } from '../../src/utils/hash';

describe('bucketOf', () => {
  it('derives bucket and sign from the family-salted FNV hash', () => {
    const h = fnv1a32('c3\u0001abc');
    expect(bucketOf('c3', 'abc', 65536)).toEqual({
      bucket: h % 65536,
      sign: (h >>> 16) & 1 ? -1 : 1,
    });
  });

  it('keeps the bucket inside [0, buckets)', () => {
    for (const b of [2, 7, 1024, 65536]) {
      const { bucket } = bucketOf('w1', 'ignore', b);
      expect(bucket).toBeGreaterThanOrEqual(0);
      expect(bucket).toBeLessThan(b);
    }
  });

  it('separates families so the same gram lands differently', () => {
    const a = bucketOf('c3', 'the', 65536);
    const b = bucketOf('w1', 'the', 65536);
    expect(a.bucket === b.bucket && a.sign === b.sign).toBe(false);
  });

  it('is deterministic', () => {
    expect(bucketOf('w2', 'ignore previous', 65536)).toEqual(bucketOf('w2', 'ignore previous', 65536));
  });
});
