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
 * Builds a character-level index map from normalized → original.
 * Characters that are removed collapse to the nearest preceding kept index.
 */
function buildIndexMap(original: string, normalized: string): number[] {
  const map: number[] = [];
  const origLower = original.toLowerCase();
  let origIdx = 0;

  for (let normIdx = 0; normIdx < normalized.length; normIdx++) {
    const target = normalized[normIdx];
    const searchStart = origIdx;
    let found = -1;

    for (let i = searchStart; i < origLower.length; i++) {
      if (origLower[i] === target) {
        found = i;
        break;
      }
    }

    if (found >= 0) {
      map.push(found);
      origIdx = found + 1;
    } else {
      // Decoded/appended content with no original counterpart — clamp to last known
      map.push(Math.max(0, Math.min(origIdx, original.length - 1)));
    }
  }

  return map;
}

export function normalize(text: string): NormalizeResult {
  // 1. NFKC + invisible/bidi/tags strip + fullwidth fold + whitespace collapse
  const afterUnicode = normalizeUnicode(text);

  // 2. Multi-pass URL/base64 decoding BEFORE homoglyph substitution
  const afterDecoding = decodeObfuscation(afterUnicode);

  // 3. Homoglyph substitution (after decoding to avoid corrupting %XX sequences)
  const afterHomoglyphs = applyHomoglyphs(afterDecoding);

  // 4. Lowercase for case-insensitive comparison baseline
  const normalized = afterHomoglyphs.toLowerCase();

  const indexMap = buildIndexMap(text, normalized);

  return { normalized, indexMap };
}
