import type { AnalyzeRoles, ChatMessage, PromptInput } from './types.js';

const DEFAULT_UNTRUSTED_ROLES = new Set(['user', 'tool', 'function']);

/**
 * True when the value looks like an OpenAI/Anthropic-style chat message list.
 */
export function isChatMessageArray(value: unknown): value is ChatMessage[] {
  if (!Array.isArray(value) || value.length === 0) return false;
  return value.every(
    (item) =>
      item !== null &&
      typeof item === 'object' &&
      typeof (item as ChatMessage).role === 'string' &&
      typeof (item as ChatMessage).content === 'string',
  );
}

function rolesToScan(analyzeRoles: AnalyzeRoles | undefined): Set<string> | 'all' {
  if (analyzeRoles === 'all') return 'all';
  if (Array.isArray(analyzeRoles) && analyzeRoles.length > 0) {
    return new Set(analyzeRoles.map((r) => r.toLowerCase()));
  }
  return DEFAULT_UNTRUSTED_ROLES;
}

/**
 * Flattens a chat transcript into a single string for pattern matching.
 * By default only untrusted roles (user / tool / function) are included so
 * system instructions do not dilute or confuse detection.
 */
export function flattenChatMessages(
  messages: ChatMessage[],
  analyzeRoles?: AnalyzeRoles,
): string {
  const roles = rolesToScan(analyzeRoles);
  const selected =
    roles === 'all'
      ? messages
      : messages.filter((m) => roles.has(m.role.toLowerCase()));

  const source = selected.length > 0 ? selected : messages;
  return source
    .map((m) => m.content.trim())
    .filter((c) => c.length > 0)
    .join('\n');
}

/**
 * Resolves either a plain string or a chat message array into text to analyze.
 */
export function resolvePromptInput(
  input: PromptInput,
  analyzeRoles?: AnalyzeRoles,
): string {
  if (typeof input === 'string') return input;
  if (!isChatMessageArray(input)) {
    throw new TypeError(
      'prompt-protection: expected a string or an array of { role, content } messages',
    );
  }
  return flattenChatMessages(input, analyzeRoles);
}
