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

/** Zero-width, invisible, and joiners */
const ZERO_WIDTH_SET = new Set([
  0x200b, 0x200c, 0x200d, 0xfeff, 0x2060, 0x180e, 0x00ad, 0x034f, 0x061c, 0x115f, 0x1160, 0x17b4,
  0x17b5, 0x3164, 0xffa0,
]);

function stripZeroWidth(text: string): string {
  let result = '';
  for (const char of text) {
    const cp = char.codePointAt(0);
    if (cp !== undefined && ZERO_WIDTH_SET.has(cp)) continue;
    result += char;
  }
  return result;
}

/** Unicode Tags block (U+E0001–U+E007F) used for invisible steganography */
const UNICODE_TAGS_RE = /[\u{E0001}-\u{E007F}]/gu;

/** Bidirectional override / embedding controls */
const BIDI_RE = /[\u202a-\u202e\u2066-\u2069]/gu;

/** Fullwidth ASCII range → ASCII (also covered partly by NFKC, belt-and-suspenders) */
const FULLWIDTH_OFFSET = 0xfee0;

/** Collapses runs of whitespace to a single space */
const WHITESPACE_RE = /\s+/g;

function collapseFullwidth(text: string): string {
  let result = '';
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    // Fullwidth A-Z, a-z, 0-9, punctuation: U+FF01–U+FF5E
    if (code >= 0xff01 && code <= 0xff5e) {
      result += String.fromCodePoint(code - FULLWIDTH_OFFSET);
    } else if (code === 0x3000) {
      result += ' ';
    } else {
      result += char;
    }
  }
  return result;
}

/** NFKC + strip invisible/bidi/tags + fullwidth fold + whitespace collapse. Does NOT apply homoglyphs. */
export function normalizeUnicode(text: string): string {
  let result = text.normalize('NFKC');
  result = result.replace(UNICODE_TAGS_RE, '');
  result = result.replace(BIDI_RE, '');
  result = stripZeroWidth(result);
  result = collapseFullwidth(result);
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
