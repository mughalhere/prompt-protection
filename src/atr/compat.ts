import type { AtrEventType, AtrSourceType } from './types.js';

/**
 * Spec §5.1 event → rule source-type table. `tool_response` additionally
 * accepts the `tool_response` source type used throughout the public rule pack.
 */
export const AGENT_SOURCE_COMPAT: Record<AtrEventType, readonly AtrSourceType[]> = {
  llm_input: ['llm_io', 'context_window'],
  llm_output: ['llm_io'],
  tool_call: ['tool_call', 'mcp_exchange'],
  tool_response: ['mcp_exchange', 'tool_response'],
  mcp_exchange: ['mcp_exchange'],
  agent_behavior: ['agent_behavior'],
  multi_agent_message: ['multi_agent_comm'],
  skill_file: ['skill_lifecycle', 'skill_permission', 'skill_chain'],
};

export function sourceCompatible(event: AtrEventType, ruleSource: AtrSourceType | undefined): boolean {
  if (ruleSource === undefined) return true;
  return AGENT_SOURCE_COMPAT[event].includes(ruleSource);
}
