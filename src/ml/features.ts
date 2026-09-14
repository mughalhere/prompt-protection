import { tokenize } from '../utils/shingle.js';
import { bucketOf } from './hash.js';
import type { GramFamily, SparseVector } from './types.js';

export const DEFAULT_BUCKETS = 65_536;
export const DEFAULT_MAX_CHARS = 4000;

export interface FeaturizeOptions {
  buckets?: number;
  maxChars?: number;
}

const CHAR_FAMILIES: ReadonlyArray<[GramFamily, number]> = [
  ['c3', 3],
  ['c4', 4],
  ['c5', 5],
];

/**
 * Binary hashed features over normalized text: char 3–5-grams of the
 * space-padded string plus word unigrams and bigrams. Output is unique per
 * (bucket, sign) and sorted by bucket, then sign, so it is reproducible.
 */
export function featurize(normalized: string, opts: FeaturizeOptions = {}): SparseVector {
  const buckets = opts.buckets ?? DEFAULT_BUCKETS;
  const maxChars = opts.maxChars ?? DEFAULT_MAX_CHARS;
  const text = normalized.length > maxChars ? normalized.slice(0, maxChars) : normalized;

  // key = bucket * 2 + (sign < 0 ? 1 : 0), so sorting keys sorts by bucket then sign.
  const keys = new Set<number>();
  const add = (family: GramFamily, gram: string): void => {
    const { bucket, sign } = bucketOf(family, gram, buckets);
    keys.add(bucket * 2 + (sign < 0 ? 1 : 0));
  };

  if (text.length > 0) {
    const padded = ` ${text} `;
    for (const [family, n] of CHAR_FAMILIES) {
      for (let i = 0; i + n <= padded.length; i++) add(family, padded.slice(i, i + n));
    }
    const words = tokenize(text);
    for (let i = 0; i < words.length; i++) {
      add('w1', words[i] as string);
      if (i + 1 < words.length) add('w2', `${words[i] as string} ${words[i + 1] as string}`);
    }
  }

  const sorted = Array.from(keys).sort((a, b) => a - b);
  const indices = new Int32Array(sorted.length);
  const signs = new Int8Array(sorted.length);
  for (let i = 0; i < sorted.length; i++) {
    const k = sorted[i] as number;
    indices[i] = k >>> 1;
    signs[i] = k & 1 ? -1 : 1;
  }
  return { indices, signs, nnz: sorted.length };
}
