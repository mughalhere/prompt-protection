import { normalize } from '../normalizer.js';
import { createClassifier } from './model.js';
import { MODEL_META, WEIGHTS_B64 } from './weights.js';

/** The embedded model shipped with the package, decoded lazily on first use. */
export const mlClassifier = createClassifier(MODEL_META, WEIGHTS_B64);

/** Convenience: normalize raw text and return the embedded model's probability. */
export function predict(text: string): number {
  return mlClassifier.predict(normalize(text).normalized);
}

export { createClassifier } from './model.js';
export { loadWeights, logitOf, predictProbability, sigmoid } from './infer.js';
export type { Model } from './infer.js';
export { fuseVerdict, ML_RULE_ID } from './fusion.js';
export { MODEL_META, WEIGHTS_B64 } from './weights.js';
export { featurize, DEFAULT_BUCKETS, DEFAULT_MAX_CHARS } from './features.js';
export type { FeaturizeOptions } from './features.js';
export { bucketOf } from './hash.js';
export type {
  Classifier,
  ClassifierMeta,
  ClassifierThresholds,
  GramFamily,
  ModelMeta,
  SparseVector,
} from './types.js';
