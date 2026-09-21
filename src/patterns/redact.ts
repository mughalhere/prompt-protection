// Redaction recognisers, run against raw text (never homoglyph-folded, digits intact).
// Secret patterns follow gitleaks' rule set (MIT, see THIRD_PARTY_NOTICES.md); PII
// recognisers follow Microsoft Presidio's (MIT). Only high-precision shapes are kept;
// Luhn / IBAN checks run in code (`src/redact.ts`), not in the regex.

export type RedactTier = 'secrets' | 'pii';

export interface RedactRule {
  id: string;
  tier: RedactTier;
  pattern: RegExp;
  /** Code-level check applied to the match; a failing check leaves the text alone. */
  validate?: 'luhn' | 'iban' | 'ssn' | 'ipv4';
  /** Regex group holding the value to redact; whole match when absent. */
  group?: number;
  description: string;
}

export const REDACT_RULES: readonly RedactRule[] = [
  // --- secrets (gitleaks) ---
  { id: 'aws-access-key-id', tier: 'secrets', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/, description: 'AWS access key id' },
  { id: 'aws-secret-key', tier: 'secrets', pattern: /(?:aws)?_?secret_?(?:access)?_?key["'=:\s]{1,5}([A-Za-z0-9/+=]{40})\b/i, group: 1, description: 'AWS secret access key' },
  { id: 'github-pat', tier: 'secrets', pattern: /\bghp_[A-Za-z0-9]{36}\b/, description: 'GitHub personal access token' },
  { id: 'github-fine-grained-pat', tier: 'secrets', pattern: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/, description: 'GitHub fine-grained PAT' },
  { id: 'github-oauth', tier: 'secrets', pattern: /\bgho_[A-Za-z0-9]{36}\b/, description: 'GitHub OAuth token' },
  { id: 'github-app-token', tier: 'secrets', pattern: /\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b/, description: 'GitHub app / server token' },
  { id: 'github-refresh', tier: 'secrets', pattern: /\bghr_[A-Za-z0-9]{36}\b/, description: 'GitHub refresh token' },
  { id: 'gitlab-pat', tier: 'secrets', pattern: /\bglpat-[A-Za-z0-9\-=_]{20,22}\b/, description: 'GitLab personal access token' },
  { id: 'slack-bot-token', tier: 'secrets', pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*\b/, description: 'Slack bot token' },
  { id: 'slack-user-token', tier: 'secrets', pattern: /\bxox[pe](?:-[0-9]{10,13}){3}-[A-Za-z0-9]{32}\b/, description: 'Slack user token' },
  { id: 'slack-webhook', tier: 'secrets', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/, description: 'Slack webhook URL' },
  { id: 'stripe-secret', tier: 'secrets', pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b/, description: 'Stripe secret / restricted key' },
  { id: 'openai-api-key', tier: 'secrets', pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/, description: 'OpenAI API key' },
  { id: 'anthropic-api-key', tier: 'secrets', pattern: /(?<![A-Za-z0-9_-])sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{90,}(?![A-Za-z0-9_-])/, description: 'Anthropic API key' },
  { id: 'google-api-key', tier: 'secrets', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, description: 'Google API key' },
  { id: 'sendgrid-api-key', tier: 'secrets', pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, description: 'SendGrid API key' },
  { id: 'twilio-api-key', tier: 'secrets', pattern: /\bSK[0-9a-fA-F]{32}\b/, description: 'Twilio API key' },
  { id: 'npm-access-token', tier: 'secrets', pattern: /\bnpm_[A-Za-z0-9]{36}\b/, description: 'npm access token' },
  { id: 'pypi-upload-token', tier: 'secrets', pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/, description: 'PyPI upload token' },
  { id: 'hashicorp-vault-token', tier: 'secrets', pattern: /\bhvs\.[A-Za-z0-9_-]{24,}\b/, description: 'HashiCorp Vault service token' },
  { id: 'private-key-block', tier: 'secrets', pattern: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----[^-]{0,4000}-----END (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----/, description: 'PEM private key block' },
  { id: 'jwt', tier: 'secrets', pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/, description: 'JSON Web Token' },
  { id: 'bearer-token', tier: 'secrets', pattern: /\bBearer\s+([A-Za-z0-9_\-.=]{24,})\b/, group: 1, description: 'Bearer token in an Authorization value' },
  { id: 'basic-auth-url', tier: 'secrets', pattern: /(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{0,15}:\/\/[^\s/:@]+:([^\s/:@]{3,})@[^\s/]+/i, group: 1, description: 'Password embedded in a URL' },
  { id: 'generic-api-key-assignment', tier: 'secrets', pattern: /\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["'\s]*[:=]["'\s]*([A-Za-z0-9_\-./+=]{24,})\b/i, group: 1, description: 'Key or token assigned to a secret-named variable' },
  // --- pii (presidio) ---
  { id: 'email-address', tier: 'pii', pattern: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![A-Za-z0-9-])/, description: 'Email address' },
  { id: 'credit-card', tier: 'pii', pattern: /\b(?:\d[ -]?){12,18}\d\b/, validate: 'luhn', description: 'Payment card number (Luhn-valid)' },
  { id: 'iban', tier: 'pii', pattern: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/, validate: 'iban', description: 'IBAN (mod-97 valid)' },
  { id: 'us-ssn', tier: 'pii', pattern: /\b(\d{3})-(\d{2})-(\d{4})\b/, validate: 'ssn', description: 'US Social Security number' },
  { id: 'phone-e164', tier: 'pii', pattern: /(?<![\w.])\+[1-9]\d{1,2}[ .-]?(?:\(?\d{1,4}\)?[ .-]?){2,4}\d{2,4}(?!\w)/, description: 'International phone number' },
  { id: 'ipv4', tier: 'pii', pattern: /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/, validate: 'ipv4', description: 'IPv4 address' },
  { id: 'ipv6', tier: 'pii', pattern: /(?<![:\w])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![:\w])/i, description: 'IPv6 address (full form)' },
];

/** Every regex above, for the ReDoS safety suite. */
export const REDACT_REGEXES: Record<string, RegExp> = Object.fromEntries(REDACT_RULES.map((r) => [r.id, r.pattern]));
