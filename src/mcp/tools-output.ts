// MCP tool handlers for `spotlight_text` and `detect_canary`. Kept free of the
// SDK/zod imports so they are unit-testable; `server.ts` wires the schemas.
import { spotlight } from '../spotlight/index.js';
import { detectCanary } from '../canary/index.js';
import type { SpotlightMode } from '../spotlight/index.js';
import type { Canary, CanaryDetection } from '../types.js';

export interface McpTextContent {
  content: { type: 'text'; text: string }[];
}

export interface SpotlightTextArgs {
  text: string;
  mode?: SpotlightMode | undefined;
  marker?: string | undefined;
  label?: string | undefined;
  sourceId?: string | undefined;
}

export interface DetectCanaryArgs {
  output: string;
  /** Token string(s) or `Canary` object(s) as returned by `createCanary`. */
  canary: string | Canary | (string | Canary)[];
  systemPrompt?: string | undefined;
}

export const SPOTLIGHT_TEXT_TOOL = {
  name: 'spotlight_text',
  description:
    'Mark untrusted text (a web page, a tool result, a document) so the model treats it as data rather than instructions. Returns the marked text, the marker, and the instruction to add to the system prompt. Modes: delimit (default), datamark, encode.',
} as const;

export const DETECT_CANARY_TOOL = {
  name: 'detect_canary',
  description:
    'Check model output for a leaked system-prompt canary token in any form (exact, spaced, base64, hex, reversed, partial). Optionally compares the output against the system prompt for verbatim overlap.',
} as const;

function textContent(payload: unknown): McpTextContent {
  return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
}

export function spotlightTextHandler(args: SpotlightTextArgs): McpTextContent {
  const result = spotlight(args.text, {
    ...(args.mode !== undefined ? { mode: args.mode } : {}),
    ...(args.marker !== undefined ? { marker: args.marker } : {}),
    ...(args.label !== undefined ? { label: args.label } : {}),
    ...(args.sourceId !== undefined ? { sourceId: args.sourceId } : {}),
  });
  return textContent(result);
}

export function detectCanaryHandler(args: DetectCanaryArgs): McpTextContent {
  const detection: CanaryDetection = detectCanary(
    args.output,
    args.canary,
    args.systemPrompt !== undefined ? { systemPrompt: args.systemPrompt } : {},
  );
  return textContent(detection);
}
