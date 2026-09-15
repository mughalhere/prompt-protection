import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { featurize, loadWeights, logitOf, sigmoid, MODEL_META, WEIGHTS_B64 } from '../../src/ml/index';
import { normalize } from '../../src/normalizer';

interface GoldenCase {
  text: string;
  normalized: string;
  nnz: number;
  features: Array<[number, number]>;
  sumInt: number;
  logit: number;
  probability: number;
}
interface Golden {
  model: { version: string; buckets: number; maxChars: number; sha256: string };
  cases: GoldenCase[];
}

const dir = join(__dirname, '__fixtures__');
const real = join(dir, 'golden.json');
const file = existsSync(real) ? real : join(dir, 'golden.placeholder.json');
const golden = JSON.parse(readFileSync(file, 'utf8')) as Golden;

describe(`golden vectors (${file.endsWith('golden.json') ? 'trained' : 'placeholder'})`, () => {
  const weights = loadWeights(MODEL_META, WEIGHTS_B64);

  it('was generated for the shipped model', () => {
    expect(golden.model).toMatchObject({
      version: MODEL_META.version,
      buckets: MODEL_META.buckets,
      maxChars: MODEL_META.maxChars,
    });
    expect(golden.cases).toHaveLength(64);
  });

  it.each(golden.cases.map((c, i) => [i, c] as const))('case %i matches exactly', (_i, c) => {
    const normalized = normalize(c.text).normalized;
    expect(normalized).toBe(c.normalized);
    const vec = featurize(normalized, { buckets: MODEL_META.buckets, maxChars: MODEL_META.maxChars });
    expect(vec.nnz).toBe(c.nnz);
    const features = Array.from({ length: vec.nnz }, (_, k) => [vec.indices[k], vec.signs[k]]);
    expect(features).toEqual(c.features);
    const { sumInt, logit } = logitOf(vec, weights, MODEL_META);
    expect(sumInt).toBe(c.sumInt);
    expect(Math.abs(logit - c.logit)).toBeLessThan(1e-6);
    expect(Math.abs(sigmoid(logit) - c.probability)).toBeLessThan(1e-6);
  });
});
