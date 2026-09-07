import { analyzePrompt, scanToolDefinition } from '../api.js';
import { analyzeOutput } from '../output.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AnalysisResult, OutputAnalysisResult, ToolDefinition } from '../types.js';

export interface ProtectionMcpServerOptions {
  /** Block cutoff passed through to the scanners. Default: library defaults. */
  threshold?: number;
  /** Optional flag band. */
  flagThreshold?: number;
}

/** Compact, user-safe verdict returned to the calling agent (no raw match text). */
function verdict(result: AnalysisResult | OutputAnalysisResult) {
  return {
    action: result.action,
    score: result.score,
    severity: result.severity,
    categories: 'categories' in result ? result.categories : result.threats,
    ruleIds: result.matches.map((m) => m.rule.id),
    blocked: result.action === 'block',
  };
}

function textContent(payload: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }] };
}

/**
 * Builds a prompt-protection MCP server exposing three scanning tools:
 * `scan_prompt`, `scan_tool_definition`, and `scan_output`. An agent can call
 * these to vet untrusted input, poisoned tool definitions, and its own output.
 *
 * The `@modelcontextprotocol/sdk` peer (and its `zod` dependency) are imported
 * dynamically, so the base package never hard-requires them.
 */
export async function createProtectionMcpServer(
  options: ProtectionMcpServerOptions = {},
): Promise<McpServer> {
  const { McpServer: Server } = await import('@modelcontextprotocol/sdk/server/mcp.js');
  const { z } = await import('zod');

  const scanOpts = {
    ...(options.threshold !== undefined ? { threshold: options.threshold } : {}),
    ...(options.flagThreshold !== undefined ? { flagThreshold: options.flagThreshold } : {}),
  };

  const server = new Server({
    name: 'prompt-protection',
    version: '2.0.0',
  });

  server.registerTool(
    'scan_prompt',
    {
      description:
        'Scan untrusted user text for prompt injection, jailbreaks, and data exfiltration before it reaches the model. Returns a verdict (allow / flag / block).',
      inputSchema: { prompt: z.string() },
    },
    ({ prompt }: { prompt: string }) => textContent(verdict(analyzePrompt(prompt, scanOpts))),
  );

  server.registerTool(
    'scan_tool_definition',
    {
      description:
        'Scan a tool/function definition (name, description, parameter schema) for tool poisoning — hidden instructions, concealment directives, or exfiltration embedded in the metadata. Call before trusting a newly discovered tool.',
      inputSchema: {
        name: z.string().optional(),
        description: z.string().optional(),
        schema: z.unknown().optional(),
      },
    },
    (args: { name?: string | undefined; description?: string | undefined; schema?: unknown }) => {
      const tool: ToolDefinition = {};
      if (args.name !== undefined) tool.name = args.name;
      if (args.description !== undefined) tool.description = args.description;
      if (args.schema !== undefined) tool.parameters = args.schema;
      return textContent(verdict(scanToolDefinition(tool, scanOpts)));
    },
  );

  server.registerTool(
    'scan_output',
    {
      description:
        'Scan model output for signs of compromise: leaked system prompts, exposed credentials, PII, or relayed injection aimed at a downstream consumer.',
      inputSchema: { output: z.string() },
    },
    ({ output }: { output: string }) => textContent(verdict(analyzeOutput(output, scanOpts))),
  );

  return server;
}
