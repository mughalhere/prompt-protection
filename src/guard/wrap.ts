import { ToolCallBlockedError } from './errors.js';
import type { GuardDecision, ToolApprovalInput, ToolApprovalOutcome, ToolCall, WrappableTool } from './types.js';

export interface WrapHooks {
  check: (call: ToolCall) => GuardDecision;
  taint: (tool: string, value: unknown, id?: string) => void;
  /** Transforms a string result before it is returned to the model. */
  mark?: (text: string, sourceId: string) => string;
}

function callIdOf(options: unknown): string | undefined {
  if (options !== null && typeof options === 'object' && 'toolCallId' in options) {
    const id = (options as { toolCallId?: unknown }).toolCallId;
    return typeof id === 'string' ? id : undefined;
  }
  return undefined;
}

/**
 * Wraps every tool's `execute`: check → execute → taint → optional spotlight.
 * Tools without `execute` (provider-executed) are returned unchanged.
 */
export function wrapTools<T extends Record<string, WrappableTool>>(tools: T, hooks: WrapHooks): T {
  const out: Record<string, WrappableTool> = {};
  for (const [name, tool] of Object.entries(tools)) {
    const execute = tool.execute;
    if (typeof execute !== 'function') {
      out[name] = tool;
      continue;
    }
    out[name] = {
      ...tool,
      execute: async (input: unknown, options?: unknown) => {
        const toolCallId = callIdOf(options);
        const decision = hooks.check({ toolName: name, args: input, ...(toolCallId !== undefined ? { toolCallId } : {}) });
        if (decision.action === 'block') throw new ToolCallBlockedError(decision);
        const result: unknown = await execute.call(tool, input, options);
        const sourceId = toolCallId ?? `${name}:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
        hooks.taint(name, result, sourceId);
        if (hooks.mark && typeof result === 'string') return hooks.mark(result, sourceId);
        return result;
      },
    };
  }
  return out as T;
}

/** Maps a guard decision onto the Vercel AI SDK `ToolApprovalStatus` values. */
export function toApprovalOutcome(decision: GuardDecision): ToolApprovalOutcome {
  const reason = decision.policy ?? decision.reasons[0];
  if (decision.action === 'block') return { type: 'denied', ...(reason !== undefined ? { reason } : {}) };
  if (decision.requiresConfirmation) return { type: 'user-approval', ...(reason !== undefined ? { reason } : {}) };
  if (decision.action === 'flag') return { type: 'approved', ...(reason !== undefined ? { reason } : {}) };
  return 'not-applicable';
}

export function createToolApproval(check: (call: ToolCall) => GuardDecision) {
  return (input: ToolApprovalInput): ToolApprovalOutcome => {
    const { toolName, input: args, toolCallId } = input.toolCall;
    return toApprovalOutcome(check({ toolName, args, ...(toolCallId !== undefined ? { toolCallId } : {}) }));
  };
}
