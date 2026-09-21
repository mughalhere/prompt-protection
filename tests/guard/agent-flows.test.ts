import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { createGuard, isDecisionReason } from '../../src/guard';
import type { GuardDecision, SinkKind } from '../../src/guard';

// Shared with bench/run.mjs so the two interpreters cannot drift.
const { runRow } = createRequire(__filename)('../../datasets/steps.cjs') as {
  runRow: (factory: typeof createGuard, row: Row) => Promise<GuardDecision>;
};

interface Row {
  id: string;
  label: 'attack' | 'benign';
  scenario: string;
  user: string;
  sources: Array<{ id: string; tool: string; text: string }>;
  steps?: Array<{ op: string } & Record<string, unknown>>;
  options?: Record<string, unknown>;
  call: { toolName: string; args: unknown; toolCallId?: string };
  sinks: Record<string, SinkKind>;
  expect: 'block' | 'flag' | 'allow';
  expect_reason: string;
  notes: string;
  known_miss?: string;
}

const rows: Row[] = readFileSync(join(__dirname, '../../datasets/agent-flows.jsonl'), 'utf8')
  .trim()
  .split('\n')
  .map((line) => JSON.parse(line) as Row);

const TARGET_AGREEMENT = 0.95;
const STEP_SCENARIOS = [
  'memory-persist', 'subagent-hop', 'split-identifier', 'approval-swap', // 4.1
  'tool-drift', 'loop-budget', 'depth-budget', // 4.2
];

describe('agent-flows.jsonl (data-driven)', () => {
  it('loads 135 rows: 100 legacy + 20 steps rows (4.1) + 15 steps rows (4.2)', () => {
    expect(rows).toHaveLength(135);
    for (const s of STEP_SCENARIOS) {
      const inScenario = rows.filter((r) => r.scenario === s);
      expect(inScenario.filter((r) => r.label === 'attack').length).toBeGreaterThanOrEqual(3);
      expect(inScenario.filter((r) => r.label === 'benign').length).toBeGreaterThanOrEqual(2);
    }
  });

  it(`agrees with expected actions on ≥ ${TARGET_AGREEMENT * 100}% of rows, and on reason codes where a row names one`, async () => {
    const mismatches: string[] = [];
    const reasonMismatches: string[] = [];
    const knownMisses: string[] = [];
    let blockedAttacks = 0;
    let attacks = 0;
    let benignBlocked = 0;
    let benign = 0;

    for (const row of rows) {
      const d = await runRow(createGuard, row);
      if (row.label === 'attack') {
        attacks++;
        if (d.action === 'block') blockedAttacks++;
      } else {
        benign++;
        if (d.action === 'block') benignBlocked++;
      }
      // Reason codes are asserted on `steps` rows only; legacy rows keep their prose reasons.
      const reasonExpected = Array.isArray(row.steps) && isDecisionReason(row.expect_reason);
      if (d.action !== row.expect && row.known_miss !== undefined) {
        knownMisses.push(`${row.id}: expected ${row.expect} got ${d.action}, ${row.known_miss}`);
      } else if (d.action !== row.expect || (reasonExpected && !d.reasons.includes(row.expect_reason))) {
        mismatches.push(
          `${row.id}: expected ${row.expect} (${row.expect_reason}) got ${d.action} (${d.reasons.join('|') || '-'})` +
            ` [policy=${d.policy ?? '-'} sink=${d.sink} flows=${d.flows.map((f) => `${f.kind}:${f.path}`).join(',') || '-'}]`,
        );
      } else if (!reasonExpected && row.expect_reason !== 'none' && d.policy !== undefined && !reasonMatches(row.expect_reason, d.policy)) {
        reasonMismatches.push(`${row.id}: expect_reason ${row.expect_reason} vs policy ${d.policy}`);
      }
    }

    const scored = rows.length - knownMisses.length;
    const agreement = (scored - mismatches.length) / scored;
    // eslint-disable-next-line no-console
    console.log(
      [
        `agent-flows: agreement ${(agreement * 100).toFixed(1)}% (${scored - mismatches.length}/${scored}, ${knownMisses.length} known miss)`,
        `block-recall on attacks: ${((blockedAttacks / attacks) * 100).toFixed(1)}%`,
        `benign blocked (FPR): ${((benignBlocked / benign) * 100).toFixed(1)}%`,
        ...mismatches.map((m) => `  MISMATCH ${m}`),
        ...knownMisses.map((m) => `  KNOWN-MISS ${m}`),
        ...reasonMismatches.map((m) => `  reason  ${m}`),
      ].join('\n'),
    );
    expect(agreement).toBeGreaterThanOrEqual(TARGET_AGREEMENT);
  });

  it('the four 4.1 scenarios agree on every row (deterministic classes)', async () => {
    const failures: string[] = [];
    for (const row of rows.filter((r) => STEP_SCENARIOS.includes(r.scenario))) {
      const d = await runRow(createGuard, row);
      if (d.action !== row.expect || (row.expect_reason !== 'none' && !d.reasons.includes(row.expect_reason))) {
        failures.push(`${row.id}: expected ${row.expect}/${row.expect_reason} got ${d.action}/${d.reasons.join('|')}`);
      }
    }
    expect(failures).toEqual([]);
  });
});

// Legacy prose reasons (rows af-001..100) map onto the policies that may legitimately decide them.
const REASON_TO_POLICIES: Record<string, string[]> = {
  'tainted-identifier-to-sink': ['untrusted-to-exfil-sink', 'untrusted-to-exec', 'untrusted-to-payment', 'injection-source-flow'],
  'tainted-content-to-sink': ['untrusted-to-exfil-sink', 'untrusted-to-exec', 'untrusted-to-payment', 'injection-source-flow'],
  'injection-source-then-sink': ['injection-then-sink'],
  'args-injection': ['args-injection', 'injection-source-flow', 'untrusted-to-exfil-sink', 'untrusted-to-exec'],
};

function reasonMatches(reason: string, policy: string): boolean {
  return (REASON_TO_POLICIES[reason] ?? []).includes(policy);
}
