import { featurize } from './features.js';
import type { ModelMeta, SparseVector } from './types.js';

export interface Model {
  meta: ModelMeta;
  weights: Int8Array;
}

const WEIGHT_CACHE = new Map<string, Int8Array>();

/** Decodes the base64 int8 weight array once per string and validates its length. */
export function loadWeights(meta: ModelMeta, b64: string): Int8Array {
  const cached = WEIGHT_CACHE.get(b64);
  if (cached !== undefined) return cached;

  const raw = atob(b64);
  if (raw.length !== meta.buckets) {
    throw new Error(
      `prompt-protection: model weights hold ${raw.length} bytes, expected ${meta.buckets}`,
    );
  }
  const weights = new Int8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    weights[i] = (raw.charCodeAt(i) << 24) >> 24;
  }
  WEIGHT_CACHE.set(b64, weights);
  return weights;
}

/** Integer dot product plus L2-binary normalisation; nnz 0 yields the bare bias. */
export function logitOf(
  vec: SparseVector,
  weights: Int8Array,
  meta: ModelMeta,
): { sumInt: number; logit: number } {
  let sumInt = 0;
  for (let i = 0; i < vec.nnz; i++) {
    sumInt += (vec.signs[i] as number) * (weights[vec.indices[i] as number] as number);
  }
  const logit = vec.nnz === 0 ? meta.bias : meta.bias + (meta.scale * sumInt) / Math.sqrt(vec.nnz);
  return { sumInt, logit };
}

export function sigmoid(logit: number): number {
  return 1 / (1 + Math.exp(-logit));
}

export function predictProbability(normalized: string, model: Model): number {
  const vec = featurize(normalized, { buckets: model.meta.buckets, maxChars: model.meta.maxChars });
  return sigmoid(logitOf(vec, model.weights, model.meta).logit);
}
