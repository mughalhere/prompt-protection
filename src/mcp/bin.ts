#!/usr/bin/env node
import { createProtectionMcpServer } from './server.js';

/**
 * CLI entry: starts the prompt-protection MCP server over stdio, so it can be
 * wired into Claude Desktop / Cursor / any MCP client via an `.mcp.json` entry:
 *
 *   { "mcpServers": { "prompt-protection": { "command": "npx",
 *       "args": ["-y", "prompt-protection-mcp"] } } }
 */
async function main(): Promise<void> {
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  const server = await createProtectionMcpServer({
    ...(process.env.PROMPT_PROTECTION_THRESHOLD
      ? { threshold: Number(process.env.PROMPT_PROTECTION_THRESHOLD) }
      : {}),
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Stay alive on stdio; the transport handles the lifecycle.
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[prompt-protection-mcp] fatal:', err);
  process.exit(1);
});
