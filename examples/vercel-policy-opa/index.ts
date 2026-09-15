// Deterministic policy (OPA / Rego) + deterministic provenance guard, composed on the
// public `toolApproval` contract. Both run on every call; the stricter verdict wins.
import { generateText, tool } from 'ai';
import { z } from 'zod';
import { createGuard } from 'prompt-protection/guard';
import { composeToolApproval, createGuardrailProvider } from 'prompt-protection/adapters/vercel-guardrail';
// import { opaToolApproval } from '@ai-sdk/policy-opa'; // see that package for the exact factory

declare const model: Parameters<typeof generateText>[0]['model'];
declare const opaToolApproval: (o: unknown) => 'approved' | 'denied' | 'user-approval' | { type: 'approved' | 'denied' | 'user-approval'; reason?: string };

const guard = createGuard({ sinks: { send_payment: 'payment', http_post: 'network', read_email: 'none' } });
const tools = {
  read_email: tool({ description: 'Read the latest email', inputSchema: z.object({}), execute: async () => 'From: vendor@example.com …' }),
  http_post: tool({ description: 'POST JSON to a URL', inputSchema: z.object({ url: z.string(), body: z.string() }), execute: async ({ url }) => `posted to ${url}` }),
  send_payment: tool({ description: 'Send a payment', inputSchema: z.object({ to: z.string(), amount: z.number() }), execute: async ({ to, amount }) => `sent ${amount} to ${to}` }),
};
const provider = createGuardrailProvider(guard, { tools: Object.keys(tools) });

export async function run(userMessage: string) {
  guard.analyzeUserTurn(userMessage); // destinations the user names become trusted
  return generateText({
    model,
    tools: guard.wrapTools(tools),
    toolApproval: composeToolApproval(opaToolApproval, provider.toolApproval()),
    onToolExecutionEnd: provider.onToolExecutionEnd(),
    prepareStep: provider.prepareStep(),
    prompt: userMessage,
  });
}
