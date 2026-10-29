import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { redact } from '../src/redact';
import { analyzeOutput } from '../src/output';

// Synthetic, format-valid values; none are live credentials.
const AWS = 'AKIAIOSFODNN7EXAMPLE';
const GH = `ghp_${'a'.repeat(36)}`;
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
const VISA = '4111 1111 1111 1111';
const IBAN = 'GB82 WEST 1234 5698 7654 32';

describe('redact', () => {
  it('replaces secrets and PII with labelled placeholders and reports original offsets', () => {
    const text = `key ${AWS} token ${GH} card ${VISA} iban ${IBAN} ssn 123-45-6789 mail bob@example.com`;
    const r = redact(text);
    expect(r.text).not.toContain(AWS);
    expect(r.text).not.toContain(GH);
    expect(r.text).not.toContain('4111');
    expect(r.text).toContain('[REDACTED:aws-access-key-id]');
    expect(r.text).toContain('[REDACTED:credit-card]');
    expect(r.text).toContain('[REDACTED:iban]');
    expect(r.text).toContain('[REDACTED:us-ssn]');
    expect(r.text).toContain('[REDACTED:email-address]');
    for (const s of r.redactions) expect(text.slice(s.start, s.end).length).toBe(s.end - s.start);
    expect(r.redactions.map((s) => s.id)).toEqual(['aws-access-key-id', 'github-pat', 'credit-card', 'iban', 'us-ssn', 'email-address']);
  });

  it('validates in code: a Luhn-invalid number, a bad IBAN and an impossible SSN are left alone', () => {
    const r = redact('card 4111 1111 1111 1112, iban GB00 WEST 1234 5698 7654 32, ssn 000-12-3456, ssn 666-12-3456, ip 999.1.1.1');
    expect(r.redactions).toEqual([]);
  });

  it('tiers and replacement are honoured; JWT and bearer tokens are secrets, phones and IPs are pii', () => {
    const text = `Authorization: Bearer ${JWT} from +44 20 7946 0958 at 10.0.0.1`;
    const secrets = redact(text, { tiers: ['secrets'], replacement: '***' });
    expect(secrets.text).toContain('***');
    expect(secrets.text).toContain('+44 20 7946 0958');
    expect(secrets.redactions.every((s) => s.tier === 'secrets')).toBe(true);
    const pii = redact(text, { tiers: ['pii'], replacement: (id) => `<${id}>` });
    expect(pii.text).toContain('<phone-e164>');
    expect(pii.text).toContain('<ipv4>');
    expect(pii.text).toContain(JWT);
  });

  it('redacts a private key block as one span', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\nabc\n-----END RSA PRIVATE KEY-----';
    const r = redact(`here: ${pem} done`);
    expect(r.text).toBe('here: [REDACTED:private-key-block] done');
  });

  it('produces zero secret-tier hits on the benign-hard dataset', () => {
    const rows = readFileSync(join(__dirname, '../datasets/benign-hard.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { text: string });
    const hits = rows.flatMap((r) => redact(r.text, { tiers: ['secrets'] }).redactions);
    expect(hits).toEqual([]);
  });

  it('analyzeOutput({ redact }) returns the redacted text without changing the verdict', () => {
    const out = `Your API key is ${AWS}. Have a nice day.`;
    const plain = analyzeOutput(out);
    const withRedact = analyzeOutput(out, { redact: 'all' });
    expect(withRedact.action).toBe(plain.action);
    expect(withRedact.redacted).toContain('[REDACTED:aws-access-key-id]');
    expect(withRedact.redactions?.[0]?.id).toBe('aws-access-key-id');
    expect(analyzeOutput(out).redacted).toBeUndefined();
  });
});
