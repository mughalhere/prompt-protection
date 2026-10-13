import { createBudget, createGuard } from '../../src/guard/index.js';

const CALL = { toolName: 'get_weather', args: { city: 'Lahore' } };

describe('createBudget', () => {
  it('counts turn calls, per-tool calls, identical repeats, depth and cost; nextTurn resets turn only', () => {
    const b = createBudget({ maxCallsPerTurn: 2, maxCallsPerTool: { http_post: 1 }, maxRepeatIdentical: 2, maxDepth: 1, maxCost: { usd: 1 } });
    b.record(CALL, 0);
    b.record(CALL, 0);
    expect(b.state.exceeded).toEqual([]);
    b.record(CALL, 0);
    expect(b.state.exceeded).toEqual(expect.arrayContaining(['calls-per-turn', 'repeat-identical']));
    b.nextTurn();
    expect(b.state.turnCalls).toBe(0);
    expect(b.state.exceeded).toEqual(['repeat-identical']);
    b.record({ toolName: 'http_post', args: { a: 1 } }, 2);
    b.record({ toolName: 'http_post', args: { a: 2 } }, 2);
    expect(b.state.exceeded).toEqual(expect.arrayContaining(['calls-per-tool:http_post', 'depth']));
    b.recordCost({ usd: 0.6 });
    b.recordCost({ usd: 0.6, tokens: 10 });
    expect(b.state.cost).toEqual({ usd: 1.2, tokens: 10 });
    expect(b.state.exceeded).toContain('cost:usd');
    b.reset();
    expect(b.state).toMatchObject({ turnCalls: 0, toolCalls: {}, repeats: {}, cost: { usd: 0, tokens: 0 }, exceeded: [] });
  });

  it('identical means canonically identical arguments (key order ignored)', () => {
    const b = createBudget({ maxRepeatIdentical: 1 });
    b.record({ toolName: 't', args: { a: 1, b: 2 } }, 0);
    b.record({ toolName: 't', args: { b: 2, a: 1 } }, 0);
    expect(b.state.exceeded).toEqual(['repeat-identical']);
    const c = createBudget({ maxRepeatIdentical: 1 });
    c.record({ toolName: 't', args: { a: 1 } }, 0);
    c.record({ toolName: 't', args: { a: 2 } }, 0);
    expect(c.state.exceeded).toEqual([]);
  });
});

describe('guard budgets', () => {
  it('off by default: budget() is zeros and never fires', () => {
    const guard = createGuard();
    for (let i = 0; i < 10; i++) expect(guard.checkToolCall(CALL).action).toBe('allow');
    expect(guard.budget()).toMatchObject({ turnCalls: 0, exceeded: [] });
    expect(guard.checkToolCall(CALL).budget).toBeUndefined();
  });

  it('the 4th identical call blocks with budget-exceeded (default maxRepeatIdentical 3), blocked attempts count', () => {
    const guard = createGuard({ budgets: {} });
    for (let i = 0; i < 3; i++) expect(guard.checkToolCall(CALL).action).toBe('allow');
    const d = guard.checkToolCall(CALL);
    expect(d.action).toBe('block');
    expect(d.policy).toBe('budget-exceeded');
    expect(d.budget?.exceeded).toEqual(['repeat-identical']);
    expect(guard.checkToolCall(CALL).action).toBe('block');
    expect(guard.budget().repeats[Object.keys(guard.budget().repeats)[0] as string]).toBe(5);
  });

  it("onExceed: 'confirm' asks instead of blocking; nextTurn resets per-turn limits", () => {
    const guard = createGuard({ budgets: { maxCallsPerTurn: 1, onExceed: 'confirm' } });
    expect(guard.checkToolCall({ toolName: 'a', args: {} }).action).toBe('allow');
    const d = guard.checkToolCall({ toolName: 'b', args: {} });
    expect(d.requiresConfirmation).toBe(true);
    expect(d.reasons).toContain('budget-exceeded');
    guard.nextTurn();
    expect(guard.checkToolCall({ toolName: 'c', args: {} }).action).toBe('allow');
  });

  it('maxDepth uses the handoff depth of the deciding guard', () => {
    const root = createGuard({ budgets: { maxDepth: 1 } });
    expect(root.checkToolCall(CALL).action).toBe('allow');
    const child = root.fork();
    expect(child.checkToolCall(CALL).action).toBe('allow');
    const grandchild = child.fork();
    const d = grandchild.checkToolCall(CALL);
    expect(d.action).toBe('block');
    expect(d.budget?.exceeded).toEqual(['depth']);
    expect(d.depth).toBe(2);
  });

  it('recordCost feeds maxCost; clear() resets the budget', () => {
    const guard = createGuard({ budgets: { maxCost: { tokens: 100 } } });
    guard.recordCost({ tokens: 101 });
    expect(guard.checkToolCall(CALL).policy).toBe('budget-exceeded');
    guard.clear();
    expect(guard.budget().cost.tokens).toBe(0);
    expect(guard.checkToolCall(CALL).action).toBe('allow');
  });
});
