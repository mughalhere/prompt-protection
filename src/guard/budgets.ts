import { digestSyncWeak } from '../utils/canonical.js';
import type { ToolCall } from './types.js';

export interface BudgetOptions {
  /** Calls the guard will see per turn (blocked attempts count; a loop of blocked calls is a loop). */
  maxCallsPerTurn?: number;
  /** Per-tool call limit across the session, one number for all tools or per name. */
  maxCallsPerTool?: number | Record<string, number>;
  /** Identical `{ toolName, args }` allowed across the session. Default 3. */
  maxRepeatIdentical?: number;
  /** Sub-agent depth allowed. */
  maxDepth?: number;
  /** Cost ceilings, fed by `guard.recordCost`. */
  maxCost?: { usd?: number; tokens?: number };
  /** Verdict when any limit is exceeded. Default `block`. */
  onExceed?: 'block' | 'confirm';
}

export interface BudgetState {
  turnCalls: number;
  toolCalls: Record<string, number>;
  /** Weak digest of `{ toolName, args }` → count. */
  repeats: Record<string, number>;
  cost: { usd: number; tokens: number };
  depth: number;
  /** Limits currently exceeded, e.g. `calls-per-turn`, `calls-per-tool:http_post`, `repeat-identical`, `depth`, `cost:usd`. */
  exceeded: string[];
  onExceed: 'block' | 'confirm';
}

export const DEFAULT_MAX_REPEAT_IDENTICAL = 3;

export interface Budget {
  /** Counts the attempt and returns the state the policies see. */
  record(call: ToolCall, depth: number): BudgetState;
  recordCost(cost: { usd?: number; tokens?: number }): BudgetState;
  readonly state: BudgetState;
  nextTurn(): void;
  reset(): void;
}

function limitFor(limit: BudgetOptions['maxCallsPerTool'], toolName: string): number | undefined {
  if (typeof limit === 'number') return limit;
  return limit?.[toolName];
}

export function createBudget(options: BudgetOptions = {}): Budget {
  const maxRepeat = options.maxRepeatIdentical ?? DEFAULT_MAX_REPEAT_IDENTICAL;
  const onExceed = options.onExceed ?? 'block';
  let state: BudgetState = fresh();

  function fresh(): BudgetState {
    return { turnCalls: 0, toolCalls: {}, repeats: {}, cost: { usd: 0, tokens: 0 }, depth: 0, exceeded: [], onExceed };
  }

  function evaluate(): void {
    const exceeded: string[] = [];
    if (options.maxCallsPerTurn !== undefined && state.turnCalls > options.maxCallsPerTurn) exceeded.push('calls-per-turn');
    for (const [tool, n] of Object.entries(state.toolCalls)) {
      const limit = limitFor(options.maxCallsPerTool, tool);
      if (limit !== undefined && n > limit) exceeded.push(`calls-per-tool:${tool}`);
    }
    if (Object.values(state.repeats).some((n) => n > maxRepeat)) exceeded.push('repeat-identical');
    if (options.maxDepth !== undefined && state.depth > options.maxDepth) exceeded.push('depth');
    if (options.maxCost?.usd !== undefined && state.cost.usd > options.maxCost.usd) exceeded.push('cost:usd');
    if (options.maxCost?.tokens !== undefined && state.cost.tokens > options.maxCost.tokens) exceeded.push('cost:tokens');
    state.exceeded = exceeded;
  }

  return {
    record(call, depth) {
      state.turnCalls += 1;
      state.toolCalls[call.toolName] = (state.toolCalls[call.toolName] ?? 0) + 1;
      const key = digestSyncWeak({ toolName: call.toolName, args: call.args });
      state.repeats[key] = (state.repeats[key] ?? 0) + 1;
      state.depth = depth;
      evaluate();
      return state;
    },
    recordCost(cost) {
      state.cost.usd += cost.usd ?? 0;
      state.cost.tokens += cost.tokens ?? 0;
      evaluate();
      return state;
    },
    get state() {
      return state;
    },
    nextTurn() {
      state.turnCalls = 0;
      evaluate();
    },
    reset() {
      state = fresh();
    },
  };
}
