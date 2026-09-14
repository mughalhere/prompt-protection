import { loadWeights, logitOf, predictProbability, sigmoid } from '../../src/ml/infer';
import { featurize } from '../../src/ml/features';
import type { ModelMeta, SparseVector } from '../../src/ml/types';

const b64 = (bytes: number[]): string => Buffer.from(Uint8Array.from(bytes)).toString('base64');

const meta = (over: Partial<ModelMeta> = {}): ModelMeta => ({
  version: 't',
  buckets: 5,
  storage: 'dense-int8',
  ngramChar: [3, 5],
  ngramWord: [1, 2],
  maxChars: 4000,
  scale: 0.5,
  bias: -1,
  norm: 'l2-binary',
  thresholds: { flag: 0.6, block: 0.9, benign: 0.1 },
  trainedAt: '',
  sha256: '',
  ...over,
});

describe('loadWeights', () => {
  it("decodes bytes as two's-complement int8 (>=128 become negative)", () => {
    const w = loadWeights(meta(), b64([0, 1, 127, 128, 255]));
    expect(Array.from(w)).toEqual([0, 1, 127, -128, -1]);
    expect(w).toBeInstanceOf(Int8Array);
  });

  it('rejects a payload whose length differs from meta.buckets', () => {
    expect(() => loadWeights(meta({ buckets: 4 }), b64([1, 2, 3]))).toThrow(/3 bytes, expected 4/);
  });

  it('caches by payload so repeated loads return the same array', () => {
    const payload = b64([9, 8, 7, 6, 5]);
    expect(loadWeights(meta(), payload)).toBe(loadWeights(meta(), payload));
  });
});

describe('logitOf', () => {
  const weights = Int8Array.from([10, -20, 30, -40, 50]);

  it('accumulates sign * weight as integers and L2-normalises by sqrt(nnz)', () => {
    const vec: SparseVector = { indices: Int32Array.from([0, 1, 4]), signs: Int8Array.from([1, -1, -1]), nnz: 3 };
    const { sumInt, logit } = logitOf(vec, weights, meta());
    expect(sumInt).toBe(10 + 20 - 50);
    expect(logit).toBeCloseTo(-1 + (0.5 * -20) / Math.sqrt(3), 12);
  });

  it('returns the bare bias when nnz is zero', () => {
    const vec: SparseVector = { indices: new Int32Array(0), signs: new Int8Array(0), nnz: 0 };
    expect(logitOf(vec, weights, meta({ bias: 2.5 }))).toEqual({ sumInt: 0, logit: 2.5 });
  });
});

describe('predictProbability', () => {
  it('is sigmoid(bias) for empty text and moves with the weights otherwise', () => {
    const m = meta({ buckets: 64, scale: 1 });
    const zero = new Int8Array(64);
    expect(predictProbability('', { meta: m, weights: zero })).toBeCloseTo(sigmoid(-1), 12);
    const vec = featurize('hello', { buckets: 64, maxChars: 4000 });
    const w = new Int8Array(64);
    for (let i = 0; i < vec.nnz; i++) w[vec.indices[i] as number] = (vec.signs[i] as number) * 100;
    expect(predictProbability('hello', { meta: m, weights: w })).toBeGreaterThan(0.99);
  });
});

describe('sigmoid', () => {
  it('maps 0 to 0.5 and is monotone', () => {
    expect(sigmoid(0)).toBe(0.5);
    expect(sigmoid(3)).toBeGreaterThan(sigmoid(-3));
  });
});
