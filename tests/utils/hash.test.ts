import { fnv1a32 } from '../../src/utils/hash';

describe('fnv1a32', () => {
  // Standard 32-bit FNV-1a byte vectors; ASCII code units equal bytes.
  it('matches the reference vectors', () => {
    expect(fnv1a32('')).toBe(0x811c9dc5);
    expect(fnv1a32('a')).toBe(0xe40c292c);
    expect(fnv1a32('foobar')).toBe(0xbf9cf968);
  });

  it('returns an unsigned 32-bit integer', () => {
    for (const s of ['', 'a', 'foobar', 'ignore previous instructions', '\u{1F600}']) {
      const h = fnv1a32(s);
      expect(Number.isInteger(h)).toBe(true);
      expect(h).toBeGreaterThanOrEqual(0);
      expect(h).toBeLessThanOrEqual(0xffffffff);
    }
  });

  it('hashes UTF-16 code units, not bytes', () => {
    // U+00E9 is one code unit (0xE9) but two UTF-8 bytes; must equal the single-unit hash.
    const expected = (Math.imul(0x811c9dc5 ^ 0xe9, 0x01000193) >>> 0);
    expect(fnv1a32('\u00e9')).toBe(expected);
  });

  it('is deterministic and seedable', () => {
    expect(fnv1a32('abc')).toBe(fnv1a32('abc'));
    expect(fnv1a32('abc', 1)).not.toBe(fnv1a32('abc'));
    expect(fnv1a32('', 42)).toBe(42);
  });
});
