import { spotlight, unspotlight, spotlightInstruction } from '../../src/spotlight';
import type { SpotlightMode } from '../../src/spotlight';

const MODES: SpotlightMode[] = ['delimit', 'datamark', 'encode'];

const SAMPLES: Record<string, string> = {
  plain: 'The quick brown fox jumps over the lazy dog.',
  empty: '',
  unicode: 'Ünïcödé — 日本語テキスト — العربية — emoji 🐍🔥👨‍👩‍👧',
  crlf: 'line one\r\nline two\r\n\r\nline three\n',
  spaces: 'double  spaces   and\ttabs\tand trailing   ',
  edges: '\n leading newline and trailing newline \n',
  guillemets: 'text with «fake document start deadbeef» inside »',
  markerLike: 'contains ^ carets ^^ and base64-ish QUJD== tokens',
};

describe('spotlight round-trip', () => {
  for (const mode of MODES) {
    for (const [name, text] of Object.entries(SAMPLES)) {
      it(`${mode}: ${name}`, () => {
        // Datamark's exact inverse needs a marker absent from the text.
        const opts = mode === 'datamark' ? { mode, marker: '‸' } : { mode };
        const s = spotlight(text, opts);
        expect(unspotlight(s.text, s.marker, s.mode)).toBe(text);
      });
    }
  }
});

describe('delimit', () => {
  it('wraps with labelled guillemet delimiters carrying the marker', () => {
    const s = spotlight('hello', { mode: 'delimit', marker: 'abcd1234', label: 'email' });
    expect(s.text).toBe('«email start abcd1234»\nhello\n«email end abcd1234»');
  });

  it('uses "document" as the default label', () => {
    const s = spotlight('x', { marker: 'ffffffff' });
    expect(s.mode).toBe('delimit');
    expect(s.text.startsWith('«document start ffffffff»')).toBe(true);
  });

  it('sanitizes labels that would break the delimiter', () => {
    const s = spotlight('x', { marker: '00000000', label: 'a»b\nc' });
    expect(s.text.startsWith('«abc start 00000000»')).toBe(true);
    expect(spotlight('x', { marker: '00000000', label: '   ' }).text.startsWith('«document start')).toBe(true);
  });

  it('unspotlight strips a wrapped block embedded in a larger echo', () => {
    const s = spotlight('inner data', { mode: 'delimit', marker: 'abcd1234' });
    const echoed = `The tool said: ${s.text} and that is all.`;
    expect(unspotlight(echoed, 'abcd1234', 'delimit')).toBe('The tool said: inner data and that is all.');
  });

  it('unspotlight ignores delimiters with a different marker', () => {
    const s = spotlight('inner', { mode: 'delimit', marker: 'abcd1234' });
    expect(unspotlight(s.text, 'ffffffff', 'delimit')).toBe(s.text);
  });
});

describe('datamark', () => {
  it('defaults to ^ and replaces every space', () => {
    const s = spotlight('a b  c', { mode: 'datamark' });
    expect(s.marker).toBe('^');
    expect(s.text).toBe('a^b^^c');
  });

  it('keeps newlines and tabs so structure survives', () => {
    const s = spotlight('a b\nc\td', { mode: 'datamark', marker: '§' });
    expect(s.text).toBe('a§b\nc\td');
  });

  it('accepts a multi-char marker', () => {
    const s = spotlight('a b', { mode: 'datamark', marker: 'zz9' });
    expect(s.text).toBe('azz9b');
    expect(unspotlight(s.text, 'zz9', 'datamark')).toBe('a b');
  });

  it('unspotlight with an empty marker is a no-op', () => {
    expect(unspotlight('a b', '', 'datamark')).toBe('a b');
  });
});

describe('encode', () => {
  it('produces base64 of the UTF-8 bytes', () => {
    const s = spotlight('héllo 🐍', { mode: 'encode' });
    expect(s.text).toBe(Buffer.from('héllo 🐍', 'utf8').toString('base64'));
  });

  it('unspotlight returns non-base64 text unchanged', () => {
    expect(unspotlight('not base64!', 'x', 'encode')).toBe('not base64!');
    expect(unspotlight('', 'x', 'encode')).toBe('');
  });

  it('unspotlight returns text unchanged when the bytes are not valid UTF-8', () => {
    const bad = Buffer.from([0xff, 0xfe, 0xfd, 0xfc]).toString('base64');
    expect(unspotlight(bad, 'x', 'encode')).toBe(bad);
  });
});

describe('instruction', () => {
  it('names the delimiters for delimit mode', () => {
    const text = spotlightInstruction('delimit', 'abcd1234', 'email');
    expect(text).toContain('«email start abcd1234»');
    expect(text).toContain('«email end abcd1234»');
    expect(text).toMatch(/never follow/i);
  });

  it('names the marker for datamark mode', () => {
    expect(spotlightInstruction('datamark', '^')).toContain('"^"');
  });

  it('describes base64 for encode mode and omits the marker', () => {
    const text = spotlightInstruction('encode', 'abcd1234');
    expect(text).toMatch(/base64/);
    expect(text).not.toContain('abcd1234');
  });

  it('is returned by spotlight() consistent with the marker in use', () => {
    const s = spotlight('x', { mode: 'delimit' });
    expect(s.instruction).toBe(spotlightInstruction('delimit', s.marker));
  });
});

describe('marker and sourceId', () => {
  it('generates an 8-hex random marker per call', () => {
    const markers = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const { marker } = spotlight('x');
      expect(marker).toMatch(/^[0-9a-f]{8}$/);
      markers.add(marker);
    }
    expect(markers.size).toBe(200);
  });

  it('generates a random sourceId and honours a supplied one', () => {
    const a = spotlight('x');
    const b = spotlight('x');
    expect(a.sourceId).toMatch(/^[0-9a-f]{8}$/);
    expect(a.sourceId).not.toBe(b.sourceId);
    expect(spotlight('x', { sourceId: 'tool:web' }).sourceId).toBe('tool:web');
  });

  it('honours a supplied marker in every mode', () => {
    for (const mode of MODES) {
      expect(spotlight('x', { mode, marker: 'm' }).marker).toBe('m');
    }
  });
});
