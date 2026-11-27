import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { EnvelopeError, open } from '../../src/envelope/index';
import type { Envelope, EnvelopeKey } from '../../src/envelope/index';
import { createGuard } from '../../src/guard/index';
import type { MemoryEntry, TaintHandoff, ToolLock, ToolSet } from '../../src/guard/index';

// JS opens what Python sealed, from the JS golden's inputs.
const JS_PATH = join(__dirname, '__fixtures__/envelope.golden.json');
const PY_PATH = join(__dirname, '../../python/tests/__fixtures__/envelope.py.golden.json');
const PY_EXISTS = existsSync(PY_PATH);
// Python has no EdDSA (deferred), so only these kinds are expected from it.
const PY_KINDS = ['hs256', 'handoff', 'memory', 'lock', 'error'];

interface Vector {
  name: string;
  kind: string;
  inputs: Record<string, unknown>;
  output: unknown;
}
interface Golden {
  header: { secret: string; now: number };
  vectors: Vector[];
}
interface ErrorOutput {
  envelope: unknown;
  code: string;
  now: number;
}

const readGolden = (path: string): Golden => JSON.parse(readFileSync(path, 'utf8')) as Golden;
const JS = readGolden(JS_PATH);
const PY = PY_EXISTS ? readGolden(PY_PATH) : undefined;
const wanted = (kind: string): Vector[] => JS.vectors.filter((v) => v.kind === kind);
const names = (kind: string): string[][] => wanted(kind).map((v) => [v.name]);

const pyVector = (name: string): Vector => {
  const found = PY?.vectors.find((v) => v.name === name);
  if (found === undefined) throw new Error(`python fixture has no vector named ${name}`);
  return found;
};
const hsKey = (inputs: Record<string, unknown>): EnvelopeKey => ({
  alg: 'HS256',
  secret: JS.header.secret,
  ...(typeof inputs.kid === 'string' ? { kid: inputs.kid } : {}),
});
const codeOf = async (attempt: Promise<unknown>): Promise<string> => {
  try {
    await attempt;
    return 'ok';
  } catch (error) {
    return error instanceof EnvelopeError ? error.code : `other:${String(error)}`;
  }
};
const reference = (taints: { tool: string; text: string }[]): [string, string][] => {
  const guard = createGuard();
  for (const t of taints) guard.taint(t.tool, t.text);
  return guard.handoff().sources.map((s) => [s.id, s.label]);
};

describe('Python-sealed envelopes under the JS implementation', () => {
  it('the Python fixture python/tests/__fixtures__/envelope.py.golden.json exists', () => {
    expect(PY_EXISTS).toBe(true);
  });

  const suite = PY_EXISTS ? describe : describe.skip;
  const each = PY_EXISTS ? it.each : it.skip.each;

  suite('fixture shape', () => {
    it('records the JS header (secret and now)', () => {
      expect(PY?.header).toEqual(JS.header);
    });

    each(JS.vectors.filter((v) => PY_KINDS.includes(v.kind)).map((v) => [v.name]))('%s: same kind and inputs as the JS golden', (name) => {
      const js = JS.vectors.find((v) => v.name === name) as Vector;
      const py = pyVector(name);
      expect(py.kind).toBe(js.kind);
      expect(py.inputs).toEqual(js.inputs);
    });
  });

  suite('hs256', () => {
    each(names('hs256'))('%s opens under JS open at its iat with the input payload, label and kid', async (name) => {
      const { inputs, output } = pyVector(name);
      const env = output as Envelope<unknown>;
      const opened = await open(env, hsKey(inputs), { now: () => env.iat });
      expect(opened.payload).toEqual(inputs.payload);
      expect(opened.label).toBe(inputs.label);
      expect(opened.kid).toBe(inputs.kid);
    });
  });

  suite('handoff', () => {
    each(names('handoff'))('%s absorbs under JS absorbSealed at its iat, labels and depth intact', async (name) => {
      const { inputs, output } = pyVector(name);
      const env = output as Envelope<TaintHandoff>;
      const child = createGuard();
      expect(await child.absorbSealed(env, hsKey(inputs), { now: () => env.iat })).toEqual({ opened: true });
      expect(child.depth).toBe(1);
      expect(child.handoff().sources.map((s) => [s.id, s.label])).toEqual(reference(inputs.taints as { tool: string; text: string }[]));
    });
  });

  suite('memory', () => {
    afterEach(() => jest.restoreAllMocks());

    each(names('memory'))('%s reads back unblocked under JS memoryReadSealed at its inner iat', async (name) => {
      const { inputs, output } = pyVector(name);
      const entry = output as MemoryEntry;
      const inner = JSON.parse(entry.sig as string) as Envelope<unknown>;
      jest.spyOn(Date, 'now').mockReturnValue(inner.iat);
      const result = await createGuard().memoryReadSealed([entry], hsKey(inputs));
      expect(result.label).toBe(entry.label);
      expect(result.label).not.toBe('blocked');
    });
  });

  suite('lock', () => {
    each(names('lock'))('%s installs under JS lock and verifies with no drift', async (name) => {
      const { inputs, output } = pyVector(name);
      const guard = createGuard();
      guard.lock(output as ToolLock);
      expect(guard.lockState.lock).toEqual(output);
      expect(await guard.verify(inputs.tools as ToolSet)).toEqual([]);
    });
  });

  suite('error', () => {
    each(names('error'))('%s fails to open with the recorded code at the recorded now', async (name) => {
      const { inputs, output } = pyVector(name);
      const { envelope, code, now } = output as ErrorOutput;
      expect(code).toBe(inputs.code);
      expect(await codeOf(open(envelope, hsKey(inputs), { now: () => now }))).toBe(code);
    });

    it('the tampered vector gives bad-signature', async () => {
      const { inputs, output } = pyVector('error-bad-signature');
      const { envelope, now } = output as ErrorOutput;
      expect(await codeOf(open(envelope, hsKey(inputs), { now: () => now }))).toBe('bad-signature');
    });
  });
});
