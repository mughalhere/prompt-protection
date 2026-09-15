import { loadWeights, predictProbability } from './infer.js';
import type { Classifier, ModelMeta } from './types.js';

/** Builds a `Classifier` over a weights file; decoding is deferred to the first `predict`. */
export function createClassifier(meta: ModelMeta, b64: string): Classifier & { readonly meta: ModelMeta } {
  let weights: Int8Array | null = null;
  return {
    meta,
    predict(normalized: string): number {
      if (weights === null) weights = loadWeights(meta, b64);
      return predictProbability(normalized, { meta, weights });
    },
  };
}
