import { analyzePrompt, scanToolDefinition } from '../api.js';
import { analyzeOutput } from '../output.js';
import { createGuard } from '../guard/guard.js';
import type { Guard, GuardDecision, GuardOptions } from '../guard/types.js';
import {
  DETECT_CANARY_TOOL,
  SPOTLIGHT_TEXT_TOOL,
  detectCanaryHandler,
  spotlightTextHandler,
} from './tools-output.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AnalysisResult, OutputAnalysisResult, ToolDefinition } from '../types.js';

export interface ProtectionMcpServerOptions {
  /** Block cutoff passed through to the scanners. Default: library defaults. */
  threshold?: number;
  /** Optional flag band. */
  flagThreshold?: number;
  /** A shared guard, or options for the one the server creates. One guard per server process. */
  guard?: Guard | GuardOptions;
}

interface InlineSource {
  id?: string | undefined;
  tool: string;
  text: string;
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

/** Guard decision without argument values: flows carry kind + path + source only. */
function guardVerdict(decision: GuardDecision) {
  return {
    action: decision.action,
    requiresConfirmation: decision.requiresConfirmation,
    blocked: decision.action === 'block',
    sink: decision.sink,
    policy: decision.policy ?? null,
    reasons: decision.reasons,
    flows: decision.flows.map((f) => ({ kind: f.kind, path: f.path, sourceId: f.sourceId })),
    argsRuleIds: decision.argsAnalysis.matches.map((m) => m.rule.id),
  };
}

function textContent(payload: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }] };
}

function isGuard(value: Guard | GuardOptions): value is Guard {
  return typeof (value as Guard).checkToolCall === 'function';
}

/**
 * Builds a prompt-protection MCP server. Scanning tools: `scan_prompt`,
 * `scan_tool_definition`, `scan_output`. Agent-security tools:
 * `register_source` + `check_tool_call` (provenance-tracked tool-call guard),
 * `spotlight_text` (untrusted-span marking) and `detect_canary` (leak check).
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
  const guard: Guard =
    options.guard !== undefined && isGuard(options.guard)
      ? options.guard
      : createGuard({ analyzeOptions: scanOpts, ...(options.guard ?? {}) });

  const server = new Server({
    name: 'prompt-protection',
    version: '3.0.0',
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

  server.registerTool(
    'register_source',
    {
      description:
        'Register an untrusted tool result (email, web page, file, RAG chunk) with the tool-call guard so later check_tool_call decisions can trace data flowing out of it. Returns the injection scan of the source.',
      inputSchema: {
        id: z.string().optional(),
        tool: z.string(),
        text: z.string(),
      },
    },
    (args: InlineSource) => {
      const source = guard.taint(args.tool, args.text, args.id !== undefined ? { id: args.id } : {});
      return textContent({ id: source.id, tool: source.tool, injection: source.injection });
    },
  );

  server.registerTool(
    'check_tool_call',
    {
      description:
        'Check a model-proposed tool call against provenance policy before executing it: blocks when untrusted data (URLs, emails, paths, verbatim payloads) flows into a network / email / exec / file / payment sink, flags when an injection-scored source preceded it. Pass `sources` for a stateless check; otherwise uses sources registered with register_source. `userText` marks destinations the user named as trusted.',
      inputSchema: {
        toolName: z.string(),
        args: z.unknown(),
        userText: z.string().optional(),
        sources: z.array(z.object({ id: z.string().optional(), tool: z.string(), text: z.string() })).optional(),
      },
    },
    (args: { toolName: string; args?: unknown; userText?: string | undefined; sources?: InlineSource[] | undefined }) => {
      const target =
        args.sources !== undefined ? createGuard({ analyzeOptions: scanOpts, ...(options.guard && !isGuard(options.guard) ? options.guard : {}) }) : guard;
      if (args.sources !== undefined) {
        for (const s of args.sources) target.taint(s.tool, s.text, s.id !== undefined ? { id: s.id } : {});
      }
      if (args.userText !== undefined) target.trust(args.userText);
      return textContent(guardVerdict(target.checkToolCall({ toolName: args.toolName, args: args.args ?? {} })));
    },
  );

  server.registerTool(
    SPOTLIGHT_TEXT_TOOL.name,
    {
      description: SPOTLIGHT_TEXT_TOOL.description,
      inputSchema: {
        text: z.string(),
        mode: z.enum(['delimit', 'datamark', 'encode']).optional(),
        marker: z.string().optional(),
        label: z.string().optional(),
        sourceId: z.string().optional(),
      },
    },
    (args: Parameters<typeof spotlightTextHandler>[0]) => ({ content: spotlightTextHandler(args).content }),
  );

  server.registerTool(
    DETECT_CANARY_TOOL.name,
    {
      description: DETECT_CANARY_TOOL.description,
      inputSchema: {
        output: z.string(),
        canary: z.union([z.string(), z.array(z.string())]),
        systemPrompt: z.string().optional(),
      },
    },
    (args: Parameters<typeof detectCanaryHandler>[0]) => ({ content: detectCanaryHandler(args).content }),
  );

  return server;
}
