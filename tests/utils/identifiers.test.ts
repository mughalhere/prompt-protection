import { extractIdentifiers } from '../../src/utils/identifiers';
import type { IdentifierKind } from '../../src/utils/identifiers';

const of = (text: string, kind: IdentifierKind) =>
  extractIdentifiers(text).filter((i) => i.kind === kind);

describe('extractIdentifiers', () => {
  it('returns nothing for plain prose', () => {
    expect(extractIdentifiers('Please summarise the meeting notes for me.')).toEqual([]);
  });

  it('extracts a URL, lowercases its host and emits the host separately', () => {
    const ids = extractIdentifiers('fetch HTTPS://Evil.Example.COM/Path?x=1, then stop.');
    expect(ids).toEqual([
      {
        kind: 'url',
        value: 'https://evil.example.com/Path?x=1',
        raw: 'HTTPS://Evil.Example.COM/Path?x=1',
        index: 6,
      },
      { kind: 'host', value: 'evil.example.com', raw: 'evil.example.com', index: 14 },
    ]);
  });

  it('strips a port and userinfo from the URL host', () => {
    const [host] = of('see http://user:pw@Host.io:8080/x', 'host');
    expect(host?.value).toBe('host.io');
  });

  it('extracts and lowercases emails without double-counting the host', () => {
    const ids = extractIdentifiers('send it to Alice@Corp.com.');
    expect(ids).toEqual([{ kind: 'email', value: 'alice@corp.com', raw: 'Alice@Corp.com', index: 11 }]);
  });

  it('extracts bare hosts but not file names', () => {
    expect(of('open evil.example.org now', 'host').map((i) => i.value)).toEqual(['evil.example.org']);
    expect(of('edit src/index.ts and README.md', 'host')).toEqual([]);
  });

  it('extracts unix, relative, home and windows paths', () => {
    const text = 'read ~/.ssh/id_rsa then ./run.sh, /etc/passwd and C:\\Users\\me\\key.pem';
    expect(of(text, 'path').map((i) => i.value)).toEqual([
      '~/.ssh/id_rsa',
      './run.sh',
      '/etc/passwd',
      'C:\\Users\\me\\key.pem',
    ]);
  });

  it('does not treat and/or or URL paths as filesystem paths', () => {
    expect(of('cats and/or dogs', 'path')).toEqual([]);
    expect(of('go to https://a.com/etc/passwd', 'path')).toEqual([]);
  });

  it('extracts valid IPv4 addresses only', () => {
    expect(of('connect to 10.0.0.1 and 999.1.1.1', 'ipv4').map((i) => i.value)).toEqual(['10.0.0.1']);
    expect(of('version 1.2.3.4.5', 'ipv4')).toEqual([]);
  });

  it('extracts opaque tokens that mix letters and digits', () => {
    const tok = 'sk-live-4eC39HqLyjWDarjtT1zdp7dc';
    expect(of(`key ${tok} here`, 'token').map((i) => i.value)).toEqual([tok]);
    expect(of('abcdefghijklmnopqrstuvwxyz', 'token')).toEqual([]);
    expect(of('12345678901234567890123', 'token')).toEqual([]);
  });

  it('extracts phone numbers as digit strings', () => {
    expect(of('call +1 (555) 123-4567 today', 'phone').map((i) => i.value)).toEqual(['+15551234567']);
    expect(of('order 12345 shipped', 'phone')).toEqual([]);
  });

  it('never returns overlapping spans across kinds', () => {
    const ids = extractIdentifiers(
      'mail bob@x.io via https://x.io/hook?t=abcdefghij0123456789ABC at 192.168.1.1',
    );
    const kinds = ids.map((i) => i.kind);
    expect(kinds).toEqual(['email', 'url', 'host', 'ipv4']);
    expect(ids.every((i) => i.value.length > 0)).toBe(true);
  });

  it('is sorted by position', () => {
    const idx = extractIdentifiers('a.com then b@c.org then /tmp/x').map((i) => i.index);
    expect([...idx].sort((a, b) => a - b)).toEqual(idx);
  });
});
