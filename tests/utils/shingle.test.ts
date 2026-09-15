import {
  CHAR_SHINGLE,
  WORD_SHINGLE,
  buildShingles,
  containment,
  tokenize,
} from '../../src/utils/shingle';
import { fnv1a32 } from '../../src/utils/hash';

describe('tokenize', () => {
  it('splits on non-alphanumerics and drops empties', () => {
    expect(tokenize('  ignore, previous!! instructions--now ')).toEqual([
      'ignore',
      'previous',
      'instructions',
      'now',
    ]);
    expect(tokenize('')).toEqual([]);
    expect(tokenize('---')).toEqual([]);
  });
});

describe('buildShingles', () => {
  it('returns empty sets for empty input', () => {
    const s = buildShingles('');
    expect(s.words.size).toBe(0);
    expect(s.chars.size).toBe(0);
    expect(s.wordCount).toBe(0);
  });

  it('emits one whole-input shingle when shorter than a window', () => {
    const s = buildShingles('send it to alice');
    expect(s.wordCount).toBe(4);
    expect(s.words).toEqual(new Set([fnv1a32('send it to alice')]));
    expect(s.chars).toEqual(new Set([fnv1a32('send it to alice')]));
  });

  it('slides word windows of WORD_SHINGLE tokens', () => {
    const words = 'a b c d e f g h'.split(' ');
    const s = buildShingles(words.join(' '));
    expect(s.words.size).toBe(words.length - WORD_SHINGLE + 1);
    expect(s.words.has(fnv1a32('a b c d e f'))).toBe(true);
    expect(s.words.has(fnv1a32('c d e f g h'))).toBe(true);
  });

  it('strides char windows by 4 by default and by 1 on request', () => {
    const text = 'x'.repeat(CHAR_SHINGLE) + 'abcdefgh';
    expect(buildShingles(text).chars.size).toBe(3);
    expect(buildShingles(text, 1).chars.size).toBe(9);
  });
});

describe('containment', () => {
  const needle = 'the secret canary phrase is purple elephant seventy';
  const hay = `some preamble here. ${needle}. and a trailer that goes on for a while.`;

  it('is zero for an empty needle', () => {
    expect(containment('', hay)).toEqual({ word: 0, char: 0, matched: 0 });
  });

  it('scores a verbatim substring as fully contained', () => {
    const c = containment(needle, hay);
    expect(c.word).toBe(1);
    expect(c.char).toBe(1);
    expect(c.matched).toBe(buildShingles(needle).words.size + buildShingles(needle).chars.size);
  });

  it('scores unrelated text as zero', () => {
    const c = containment(needle, 'completely different content about cooking pasta at home tonight');
    expect(c.word).toBe(0);
    expect(c.char).toBe(0);
  });

  it('scores a partial overlap between 0 and 1', () => {
    const c = containment(needle, `${needle.slice(0, 30)} then something else entirely`);
    expect(c.char).toBeGreaterThan(0);
    expect(c.char).toBeLessThan(1);
  });

  it('accepts prebuilt shingle sets', () => {
    const c = containment(buildShingles(needle), buildShingles(hay, 1));
    expect(c.word).toBe(1);
    expect(c.char).toBe(1);
  });
});
