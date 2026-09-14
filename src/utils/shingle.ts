import { fnv1a32 } from './hash.js';

export const WORD_SHINGLE = 6;
export const CHAR_SHINGLE = 24;
export const CHAR_STRIDE = 4;

export interface ShingleSet {
  words: Set<number>;
  chars: Set<number>;
  wordCount: number;
}

export interface Containment {
  /** Fraction of needle word shingles found in the hay. */
  word: number;
  /** Fraction of needle char shingles found in the hay. */
  char: number;
  /** Absolute count of matched shingles (word + char). */
  matched: number;
}

const EMPTY: Containment = { word: 0, char: 0, matched: 0 };

/** Splits already-normalized text into lowercase alphanumeric tokens. */
export function tokenize(normalized: string): string[] {
  return normalized.split(/[^a-z0-9]+/).filter((t) => t.length > 0);
}

/**
 * Hashes overlapping word and char windows. Inputs shorter than a window
 * yield one shingle of the whole input so short needles remain matchable.
 * `charStride` 1 indexes every offset (use for the hay side of a containment).
 */
export function buildShingles(normalized: string, charStride: number = CHAR_STRIDE): ShingleSet {
  const words = new Set<number>();
  const chars = new Set<number>();
  const tokens = tokenize(normalized);

  if (tokens.length > 0 && tokens.length < WORD_SHINGLE) {
    words.add(fnv1a32(tokens.join(' ')));
  } else {
    for (let i = 0; i + WORD_SHINGLE <= tokens.length; i++) {
      words.add(fnv1a32(tokens.slice(i, i + WORD_SHINGLE).join(' ')));
    }
  }

  const stride = Math.max(1, Math.floor(charStride));
  if (normalized.length > 0 && normalized.length < CHAR_SHINGLE) {
    chars.add(fnv1a32(normalized));
  } else {
    for (let i = 0; i + CHAR_SHINGLE <= normalized.length; i += stride) {
      chars.add(fnv1a32(normalized.slice(i, i + CHAR_SHINGLE)));
    }
  }

  return { words, chars, wordCount: tokens.length };
}

function fraction(needle: Set<number>, hay: Set<number>): { ratio: number; hits: number } {
  if (needle.size === 0) return { ratio: 0, hits: 0 };
  let hits = 0;
  for (const h of needle) if (hay.has(h)) hits++;
  return { ratio: hits / needle.size, hits };
}

/**
 * Fraction of `needle` shingles present in `hay`. String hay is indexed at
 * every char offset so a verbatim substring scores char containment 1.
 */
export function containment(needle: string | ShingleSet, hay: string | ShingleSet): Containment {
  const n = typeof needle === 'string' ? buildShingles(needle) : needle;
  if (n.words.size === 0 && n.chars.size === 0) return EMPTY;
  const h = typeof hay === 'string' ? buildShingles(hay, 1) : hay;
  const w = fraction(n.words, h.words);
  const c = fraction(n.chars, h.chars);
  return { word: w.ratio, char: c.ratio, matched: w.hits + c.hits };
}
