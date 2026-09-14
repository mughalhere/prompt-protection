import { performance } from 'node:perf_hooks';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzePrompt } from '../../src/api';
import { mlClassifier } from '../../src/ml/index';
import { normalize } from '../../src/normalizer';

const lines = (f: string) =>
  readFileSync(join(__dirname, '..', '__fixtures__', f), 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

const corpus = [...lines('malicious.txt'), ...lines('benign.txt')];
const ROUNDS = 20;

function bench(fn: (text: string) => unknown): { p50: number; p99: number; max: number } {
  for (const text of corpus) fn(text);
  const samples: number[] = [];
  for (let r = 0; r < ROUNDS; r++) {
    for (const text of corpus) {
      const t0 = performance.now();
      fn(text);
      samples.push(performance.now() - t0);
    }
  }
  const sorted = samples.sort((a, b) => a - b);
  const at = (q: number) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))] as number;
  return { p50: at(0.5), p99: at(0.99), max: at(1) };
}

const report = (name: string, s: ReturnType<typeof bench>): void => {
  process.stdout.write(`${name}: p50 ${s.p50.toFixed(4)} ms, p99 ${s.p99.toFixed(4)} ms, max ${s.max.toFixed(4)} ms\n`);
};

// Sanity bounds only: jest's parallel workers add jitter. bench/ reports the real p50/p99.
describe('ml latency', () => {
  it('predict stays in the low-millisecond range over the fixtures', () => {
    const normalized = corpus.map((t) => normalize(t).normalized);
    let i = 0;
    const stats = bench(() => mlClassifier.predict(normalized[i++ % normalized.length] as string));
    report('predict', stats);
    expect(stats.p99).toBeLessThan(10);
  });

  it("analyzePrompt with ml: 'escalate' stays in the low-millisecond range", () => {
    const stats = bench((t) => analyzePrompt(t, { ml: 'escalate' }));
    report('analyzePrompt+ml', stats);
    expect(stats.p99).toBeLessThan(10);
  });
});
