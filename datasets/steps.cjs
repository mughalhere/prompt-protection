'use strict';
// Shared interpreter for datasets/agent-flows.jsonl rows, used by tests/guard/agent-flows.test.ts (src)
// and bench/run.mjs (dist). A row without `steps` is the legacy shape: user → sources → call.
// With `steps`, each op runs in order and `row.call` is still the final, scored call.

const CLOCK_START = 1_700_000_000_000;

const OPS = new Set([
  'trust', 'taint', 'memoryWrite', 'memoryRead', 'newGuard', 'fork', 'nextTurn', 'approve', 'advanceClock', 'call',
  // 4.2
  'pin', 'lock', 'redefineTool', 'recordCost',
]);

/**
 * @param {(options?: object) => any} createGuard
 * @param {any} row
 * @returns {Promise<any>} the GuardDecision for `row.call`
 */
async function runRow(createGuard, row) {
  let now = CLOCK_START;
  const base = { ...(row.options ?? {}), sinks: row.sinks ?? {} };
  base.approvals = { ...(base.approvals ?? {}), now: () => now };
  let guard = createGuard(base);
  if (row.user) guard.analyzeUserTurn(row.user);
  for (const s of row.sources ?? []) guard.taint(s.tool, s.text, { id: s.id });
  if (!Array.isArray(row.steps)) return guard.checkToolCall(row.call);

  const memory = new Map();
  let tools = {};
  for (const step of row.steps) {
    if (!OPS.has(step.op)) throw new Error(`${row.id}: unknown step op ${step.op}`);
    switch (step.op) {
      case 'trust':
        guard.analyzeUserTurn(step.text);
        break;
      case 'taint':
        guard.taint(step.tool, step.text, { id: step.id });
        break;
      case 'memoryWrite': {
        const opts = { id: step.id, policy: step.policy ?? 'annotate' };
        if (step.key !== undefined) opts.key = step.key;
        if (step.derivedFrom !== undefined) opts.derivedFrom = step.derivedFrom;
        memory.set(step.id, guard.taintMemoryWrite(step.tool, step.text, opts).entry);
        break;
      }
      case 'memoryRead': {
        const entries = step.ids.map((id) => memory.get(id));
        if (entries.some((e) => e === undefined)) throw new Error(`${row.id}: memoryRead of an unwritten id`);
        guard.memoryRead(entries);
        break;
      }
      case 'newGuard':
        guard = createGuard(base);
        break;
      case 'fork':
        guard = guard.fork();
        break;
      case 'nextTurn':
        guard.nextTurn();
        break;
      case 'approve': {
        const call = { toolName: step.toolName, args: step.args };
        if (step.toolCallId !== undefined) call.toolCallId = step.toolCallId;
        const card = await guard.approvalCard(call);
        guard.confirm(card.id, card.digest, step.by);
        break;
      }
      case 'advanceClock':
        now += step.ms;
        break;
      case 'pin': {
        // `tools` is a name → { description, inputSchema?, annotations? } map; the row-local copy is what later steps redefine.
        tools = JSON.parse(JSON.stringify(step.tools));
        await guard.pin(tools, step.drift !== undefined ? { drift: step.drift } : {});
        break;
      }
      case 'lock':
        guard.lock(step.lock, step.drift !== undefined ? { drift: step.drift } : {});
        break;
      case 'redefineTool': {
        // A definition changed at runtime (poisoned description, new schema); wrapTools is where a guard sees definitions.
        tools = { ...tools, [step.name]: { ...(tools[step.name] ?? {}), ...step.tool } };
        guard.wrapTools(tools);
        break;
      }
      case 'recordCost':
        guard.recordCost(step.cost);
        break;
      case 'call': {
        const call = { toolName: step.toolName, args: step.args };
        if (step.toolCallId !== undefined) call.toolCallId = step.toolCallId;
        guard.checkToolCall(call);
        break;
      }
      default:
        break;
    }
  }
  return guard.checkToolCall(row.call);
}

module.exports = { runRow, OPS: [...OPS], CLOCK_START };
