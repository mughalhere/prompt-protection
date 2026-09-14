/** Decision thresholds on the classifier's probability output, fixed at training time. */
export interface ClassifierThresholds {
  /** p ≥ flag → at least `flag` when rules allowed. */
  flag: number;
  /** p ≥ block → escalate to `block`. */
  block: number;
  /** p ≤ benign → a weak rules-only block may be downgraded (hybrid mode only). */
  benign: number;
}

export interface ClassifierMeta {
  version: string;
  buckets: number;
  thresholds: ClassifierThresholds;
}

/** Full weights-file contract written by `training/export.py` (`src/ml/weights.ts`). */
export interface ModelMeta extends ClassifierMeta {
  storage: 'dense-int8';
  ngramChar: readonly [number, number];
  ngramWord: readonly [number, number];
  maxChars: number;
  /** Dequantisation factor: w = q * scale. */
  scale: number;
  /** Float32 intercept. */
  bias: number;
  /** logit = bias + scale * sumInt / sqrt(nnz). */
  norm: 'l2-binary';
  trainedAt: string;
  /** SHA-256 hex of the raw int8 byte array. */
  sha256: string;
}

/** Embedded model contract: probability of injection for already-normalized text. */
export interface Classifier {
  predict(normalized: string): number;
  readonly meta: ClassifierMeta;
}

/** Hashed binary feature vector: bucket indices with their alternate signs. */
export interface SparseVector {
  indices: Int32Array;
  signs: Int8Array;
  nnz: number;
}

export type GramFamily = 'c3' | 'c4' | 'c5' | 'w1' | 'w2';
