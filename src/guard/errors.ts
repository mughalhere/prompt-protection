import type { GuardDecision } from './types.js';

/** Thrown by `wrapTools` / `verify` paths when the guard blocks a tool call. */
export class ToolCallBlockedError extends Error {
  readonly decision: GuardDecision;

  constructor(decision: GuardDecision) {
    const policy = decision.policy ?? 'guard';
    super(
      `prompt-protection: tool call "${decision.toolName}" blocked by ${policy} (sink ${decision.sink}, ${decision.flows.length} flow(s))`,
    );
    this.name = 'ToolCallBlockedError';
    this.decision = decision;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
