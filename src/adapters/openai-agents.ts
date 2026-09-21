/**
 * @packageDocumentation
 * @beta Preview tier: may change in a minor release. See docs/API_STABILITY.md.
 */
// OpenAI Agents JS (`@openai/agents` ≥ 0.18) adapter. Structural `*Like` types mirror the SDK's
// guardrail and tool shapes so this compiles and runs without the peer installed.
import { denial, errorMessage, guarded } from './protect-core.js';
import type { FailMode } from '../types.js';
import type { Guard, GuardDecision } from '../guard/types.js';

/** `InputGuardrail`: `{ name, execute({ agent, input, context }) → { tripwireTriggered, outputInfo } }`. */
export interface InputGuardrailLike {
  name: string;
  execute(args: { agent: unknown; input: string | Array<Record<string, unknown>>; context: unknown }): Promise<{ tripwireTriggered: boolean; outputInfo: unknown }>;
  runInParallel?: boolean;
}

/** `ToolInputGuardrailDefinition`: `run(data: { context, agent, toolCall }) → { behavior, outputInfo? }`. */
export interface ToolInputGuardrailLike {
  type: 'tool_input';
  name: string;
  run(data: { context: unknown; agent: unknown; toolCall: FunctionCallLike }): Promise<ToolGuardrailOutputLike>;
}

export interface ToolOutputGuardrailLike {
  type: 'tool_output';
  name: string;
  run(data: { context: unknown; agent: unknown; toolCall: FunctionCallLike; output: unknown }): Promise<ToolGuardrailOutputLike>;
}

export interface FunctionCallLike {
  name: string;
  arguments: string;
  callId?: string;
}

export interface ToolGuardrailOutputLike {
  behavior: { type: 'allow' } | { type: 'rejectContent'; message: string } | { type: 'throwException' };
  outputInfo?: unknown;
}

/** The subset of `tool({ ... })` options this adapter reads and extends. */
export interface FunctionToolLike {
  name: string;
  needsApproval?: boolean | ((runContext: unknown, input: unknown, callId?: string) => Promise<boolean>);
  inputGuardrails?: ToolInputGuardrailLike[];
  outputGuardrails?: ToolOutputGuardrailLike[];
  [key: string]: unknown;
}

export interface OpenAIAgentsProtectOptions {
  /** Verdict when a hook throws: `closed` (default) rejects, `open` allows. */
  failMode?: FailMode;
  /** Score the agent's text input through the guard's session (`analyzeUserTurn`). Default true. */
  scoreInput?: boolean;
}

export interface OpenAIAgentsProtected {
  /** Add to `new Agent({ inputGuardrails })`: trips on a block-level prompt and trusts what the user named. */
  inputGuardrails: InputGuardrailLike[];
  /** Tool-level guardrails to add to each `tool({ inputGuardrails, outputGuardrails })`. */
  toolInputGuardrail: ToolInputGuardrailLike;
  toolOutputGuardrail: ToolOutputGuardrailLike;
  /** `needsApproval` policy for one tool: true when the guard says `confirm` (or errors under `closed`). */
  needsApproval: (toolName: string) => (runContext: unknown, input: unknown, callId?: string) => Promise<boolean>;
  /** Returns a copy of a `tool()` definition carrying all three hooks (existing hooks kept). */
  wrapTool<T extends FunctionToolLike>(tool: T): T;
  /** Most recent decision per tool call id. */
  lastDecision(callId: string): GuardDecision | undefined;
}

function parseArgs(raw: string): unknown {
  try {
    return raw.length > 0 ? (JSON.parse(raw) as unknown) : {};
  } catch {
    return { raw };
  }
}

function textOf(input: string | Array<Record<string, unknown>>): string {
  if (typeof input === 'string') return input;
  return input
    .map((item) => {
      const content = item.content;
      if (typeof content === 'string') return content;
      if (Array.isArray(content)) return content.map((c) => (typeof c === 'object' && c !== null && typeof (c as { text?: unknown }).text === 'string' ? (c as { text: string }).text : '')).join('\n');
      return '';
    })
    .join('\n');
}

/**
 * Hooks for OpenAI Agents JS: an agent input guardrail, tool input/output guardrails and a
 * `needsApproval` policy, all driven by one guard. Tool results are tainted as they return; a
 * tool call whose arguments carry tainted data into a sink is rejected with the reason.
 */
export function protect(guard: Guard, options: OpenAIAgentsProtectOptions = {}): OpenAIAgentsProtected {
  const failMode = options.failMode ?? 'closed';
  const scoreInput = options.scoreInput ?? true;
  const reject = (message: string): ToolGuardrailOutputLike => ({ behavior: { type: 'rejectContent', message } });
  const allow: ToolGuardrailOutputLike = { behavior: { type: 'allow' } };

  type GuardrailOutput = { tripwireTriggered: boolean; outputInfo: unknown };
  const inputGuardrail: InputGuardrailLike = {
    name: 'prompt-protection',
    execute: ({ input }) =>
      guarded<GuardrailOutput>(
        () => {
          const text = textOf(input);
          if (!scoreInput) {
            guard.trust(text);
            return { tripwireTriggered: false, outputInfo: { action: 'allow' } };
          }
          const result = guard.analyzeUserTurn(text);
          return { tripwireTriggered: result.action === 'block', outputInfo: { action: result.action, score: result.score, categories: result.categories } };
        },
        failMode,
        {
          closed: (err) => ({ tripwireTriggered: true, outputInfo: { error: errorMessage(err) } }),
          open: (err) => ({ tripwireTriggered: false, outputInfo: { error: errorMessage(err) } }),
        },
      ),
  };

  const check = (toolCall: FunctionCallLike): GuardDecision =>
    guard.checkToolCall({ toolName: toolCall.name, args: parseArgs(toolCall.arguments), ...(toolCall.callId !== undefined ? { toolCallId: toolCall.callId } : {}) });

  const toolInputGuardrail: ToolInputGuardrailLike = {
    type: 'tool_input',
    name: 'prompt-protection',
    run: ({ toolCall }) =>
      guarded(
        () => {
          const d = check(toolCall);
          if (d.action === 'block') return reject(denial(d).message);
          return { ...allow, outputInfo: { action: d.action, reasons: d.reasons } };
        },
        failMode,
        { closed: (err) => reject(`prompt-protection: guard error (${errorMessage(err)})`), open: () => allow },
      ),
  };

  const toolOutputGuardrail: ToolOutputGuardrailLike = {
    type: 'tool_output',
    name: 'prompt-protection',
    run: ({ toolCall, output }) =>
      guarded(
        () => {
          const src = guard.taint(toolCall.name, output, toolCall.callId !== undefined ? { id: toolCall.callId } : {});
          return { ...allow, outputInfo: { sourceId: src.id, injection: src.injection.action } };
        },
        failMode,
        { closed: (err) => reject(`prompt-protection: taint error (${errorMessage(err)})`), open: () => allow },
      ),
  };

  // The SDK's hook does not receive the tool name, so the policy is bound per tool.
  const needsApproval: OpenAIAgentsProtected['needsApproval'] = (toolName) => (_runContext, input, callId) =>
    guarded(
      () => guard.checkToolCall({ toolName, args: input, ...(callId !== undefined ? { toolCallId: callId } : {}) }).requiresConfirmation,
      failMode,
      { closed: () => true, open: () => false },
    );

  return {
    inputGuardrails: [inputGuardrail],
    toolInputGuardrail,
    toolOutputGuardrail,
    needsApproval,
    wrapTool(tool) {
      const prior = tool.needsApproval;
      const ours = needsApproval(tool.name);
      const bound: FunctionToolLike['needsApproval'] = async (runContext, input, callId) => {
        if (await ours(runContext, input, callId)) return true;
        if (typeof prior === 'function') return prior(runContext, input, callId);
        return prior === true;
      };
      return {
        ...tool,
        needsApproval: bound,
        inputGuardrails: [...(tool.inputGuardrails ?? []), toolInputGuardrail],
        outputGuardrails: [...(tool.outputGuardrails ?? []), toolOutputGuardrail],
      };
    },
    lastDecision: (callId) => guard.lastDecision(callId),
  };
}
