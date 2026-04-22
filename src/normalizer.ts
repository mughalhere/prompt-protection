import { normalizeUnicode, applyHomoglyphs } from './utils/unicode.js';
import { decodeObfuscation } from './utils/encoding.js';

export interface NormalizeResult {
  /** The normalized text used for pattern matching */
  normalized: string;
  /**
   * Maps each character index in `normalized` back to the corresponding
   * index in the original string. Used by stripPrompt to restore original positions.
   */
  indexMap: number[];
}

/**
 * Builds a character-level index map from original → normalized.
 * Characters that are removed collapse to the nearest preceding kept index.
 */
function buildIndexMap(original: string, normalized: string): number[] {
  // Simple heuristic: the map is built by aligning characters that survived.
  // Since normalization changes string length, we track original positions.
  const map: number[] = [];
  let origIdx = 0;

  for (let normIdx = 0; normIdx < normalized.length; normIdx++) {
    // Advance origIdx until we find the matching char or give up
    while (origIdx < original.length && normalized[normIdx] !== original[origIdx]?.toLowerCase()) {
      origIdx++;
    }
    map.push(origIdx);
    if (origIdx < original.length) origIdx++;
  }

  return map;
}

export function normalize(text: string): NormalizeResult {
  // 1. NFKC normalisation + zero-width strip + whitespace collapse
  const afterUnicode = normalizeUnicode(text);

  // 2. URL/base64 decoding BEFORE homoglyph substitution so %20 doesn't become %2o
  const afterDecoding = decodeObfuscation(afterUnicode);

  // 3. Homoglyph substitution (after decoding to avoid corrupting %XX sequences)
  const afterHomoglyphs = applyHomoglyphs(afterDecoding);

  // 4. Lowercase for case-insensitive comparison baseline
  const normalized = afterHomoglyphs.toLowerCase();

  // Build index map against the original text for span restoration
  const indexMap = buildIndexMap(text.toLowerCase(), normalized);

  return { normalized, indexMap };
}
