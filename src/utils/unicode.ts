const HOMOGLYPH_MAP: Record<string, string> = {
  // digits → letters
  '0': 'o',
  '1': 'i',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '6': 'g',
  '7': 't',
  '8': 'b',
  // symbols → letters
  '@': 'a',
  '$': 's',
  '!': 'i',
  // common Cyrillic/Greek lookalikes handled by NFKC, but a few slip through
  'а': 'a', // Cyrillic а
  'е': 'e', // Cyrillic е
  'о': 'o', // Cyrillic о
  'р': 'r', // Cyrillic р
  'с': 'c', // Cyrillic с
  'х': 'x', // Cyrillic х
  'і': 'i', // Cyrillic і
  'Ι': 'i', // Greek Ι
  'ο': 'o', // Greek ο
};

/** Strips zero-width and invisible characters */
const ZERO_WIDTH_RE = /\u200b|\u200c|\u200d|\ufeff|\u2060|\u180e/gu;

/** Collapses runs of whitespace to a single space */
const WHITESPACE_RE = /\s+/g;

/** NFKC normalisation + zero-width strip + whitespace collapse. Does NOT apply homoglyphs. */
export function normalizeUnicode(text: string): string {
  let result = text.normalize('NFKC');
  result = result.replace(ZERO_WIDTH_RE, '');
  result = result.replace(WHITESPACE_RE, ' ').trim();
  return result;
}

/** Applies homoglyph substitution. Run this AFTER URL/base64 decoding. */
export function applyHomoglyphs(text: string): string {
  let result = '';
  for (const char of text) {
    result += HOMOGLYPH_MAP[char] ?? char;
  }
  return result;
}
