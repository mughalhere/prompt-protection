/**
 * @packageDocumentation
 * @beta Preview tier: may change in a minor release. See docs/API_STABILITY.md.
 */
// LangChain.js (`langchain` ≥ 1) agent middleware. `langchain` and `@langchain/core` are optional
// peers, dynamic-imported; the exported shapes are structural so this compiles without them.
import { denial, errorMessage, guarded } from './protect-core.js';
import type { FailMode } from '../types.js';
import type { Guard, GuardDecision } from '../guard/types.js';

export interface ToolCallLike {
  name: string;
  args: Record<string, unknown>;
  id?: string;
}

/** `ToolCallRequest` from `langchain/agents/middleware`: `{ toolCall, tool, state, runtime }`. */
export interface ToolCallRequestLike {
  toolCall: ToolCallLike;
  tool?: unknown;
  state: Record<string, unknown>;
  runtime: unknown;
}

export interface ToolMessageLike {
  tool_call_id?: string;
  content: unknown;
  status?: 'success' | 'error';
  name?: string;
}

/** The hooks this adapter fills on `createMiddleware({ ... })`. */
export interface AgentMiddlewareLike {
  name: string;
  wrapToolCall(request: ToolCallRequestLike, handler: (request: ToolCallRequestLike) => Promise<unknown>): Promise<unknown>;
  beforeModel(state: Record<string, unknown>, runtime: unknown): Promise<undefined>;
}

export interface LangChainProtectOptions {
  failMode?: FailMode;
  /** Score the latest human message through the guard's session before each model call. Default true. */
  scoreInput?: boolean;
}

interface CreateMiddlewareFn {
  (config: Record<string, unknown>): AgentMiddlewareLike;
}
interface ToolMessageCtor {
  new (fields: ToolMessageLike): unknown;
}

// Specifiers held in variables so TypeScript does not resolve peers that are not installed here.
const LANGCHAIN = 'langchain';
const LANGCHAIN_MESSAGES = '@langchain/core/messages';

async function loadLangchain(): Promise<{ createMiddleware: CreateMiddlewareFn; ToolMessage: ToolMessageCtor }> {
  const [lc, core] = (await Promise.all([import(LANGCHAIN), import(LANGCHAIN_MESSAGES)])) as [
    { createMiddleware: CreateMiddlewareFn },
    { ToolMessage: ToolMessageCtor },
  ];
  return { createMiddleware: lc.createMiddleware, ToolMessage: core.ToolMessage };
}

function latestHumanText(state: Record<string, unknown>): string | null {
  const messages = state.messages;
  if (!Array.isArray(messages)) return null;
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i] as { type?: string; _getType?: () => string; content?: unknown; role?: string } | undefined;
    const type = m?._getType?.() ?? m?.type ?? m?.role;
    if (type === 'human' || type === 'user') return typeof m?.content === 'string' ? m.content : JSON.stringify(m?.content ?? '');
  }
  return null;
}

function contentOf(message: unknown): unknown {
  if (message !== null && typeof message === 'object' && 'content' in message) return (message as { content: unknown }).content;
  return message;
}

/** Hook bodies, independent of the peer; `protect()` binds them into a real middleware. */
export function hooks(guard: Guard, ToolMessage: ToolMessageCtor, options: LangChainProtectOptions = {}): Pick<AgentMiddlewareLike, 'wrapToolCall' | 'beforeModel'> {
  const failMode = options.failMode ?? 'closed';
  const scoreInput = options.scoreInput ?? true;
  const seenHuman = new Set<string>();

  const deny = (d: GuardDecision | null, toolCall: ToolCallLike, err?: unknown): unknown =>
    new ToolMessage({
      ...(toolCall.id !== undefined ? { tool_call_id: toolCall.id } : {}),
      name: toolCall.name,
      status: 'error',
      content: d !== null ? denial(d).message : `prompt-protection: guard error (${errorMessage(err)})`,
    });

  return {
    wrapToolCall: (request, handler) =>
      guarded(
        async () => {
          const { toolCall } = request;
          const d = guard.checkToolCall({ toolName: toolCall.name, args: toolCall.args, ...(toolCall.id !== undefined ? { toolCallId: toolCall.id } : {}) });
          if (d.action === 'block') return deny(d, toolCall);
          const result = await handler(request);
          guard.taint(toolCall.name, contentOf(result), toolCall.id !== undefined ? { id: toolCall.id } : {});
          return result;
        },
        failMode,
        { closed: (err) => deny(null, request.toolCall, err), open: () => handler(request) },
      ),
    beforeModel: (state) =>
      guarded(
        () => {
          if (!scoreInput) return undefined;
          const text = latestHumanText(state);
          if (text === null || seenHuman.has(text)) return undefined;
          seenHuman.add(text);
          guard.analyzeUserTurn(text);
          return undefined;
        },
        failMode,
        { closed: () => undefined, open: () => undefined },
      ),
  };
}

/**
 * `createMiddleware({ name: 'prompt-protection', wrapToolCall, beforeModel })` from the installed
 * `langchain`. Denied calls return an error `ToolMessage` (the model sees the reason); results are
 * tainted; the latest human message trusts the destinations it names.
 */
export async function protect(guard: Guard, options: LangChainProtectOptions = {}): Promise<AgentMiddlewareLike> {
  const { createMiddleware, ToolMessage } = await loadLangchain();
  return createMiddleware({ name: 'prompt-protection', ...hooks(guard, ToolMessage, options) });
}

/** `when` predicate for `humanInTheLoopMiddleware`'s `interruptOn`: interrupt when the guard says `confirm`. */
export function interruptWhen(guard: Guard): (request: { toolCall: ToolCallLike }) => boolean {
  return ({ toolCall }) => {
    try {
      const d = guard.checkToolCall({ toolName: toolCall.name, args: toolCall.args, ...(toolCall.id !== undefined ? { toolCallId: toolCall.id } : {}) });
      return d.requiresConfirmation || d.action === 'block';
    } catch {
      return true;
    }
  };
}
