import { ClaudeAdapter } from '../../src/adapters/claude';

const create = jest.fn();

jest.mock('@anthropic-ai/sdk', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => ({ messages: { create } })),
}));

const adapter = new ClaudeAdapter({ apiKey: 'test' });

describe('ClaudeAdapter', () => {
  beforeEach(() => create.mockReset());

  it('reads the verdict from the text block, not content[0]', async () => {
    create.mockResolvedValue({
      stop_reason: 'end_turn',
      content: [
        { type: 'thinking', thinking: '' },
        { type: 'text', text: 'MALICIOUS' },
      ],
    });
    await expect(adapter.analyze('x')).resolves.toMatchObject({ isMalicious: true });
  });

  it('returns safe for a SAFE verdict', async () => {
    create.mockResolvedValue({ stop_reason: 'end_turn', content: [{ type: 'text', text: 'SAFE' }] });
    await expect(adapter.analyze('x')).resolves.toEqual({ isMalicious: false });
  });

  it('throws instead of reporting safe when no text block comes back', async () => {
    create.mockResolvedValue({ stop_reason: 'max_tokens', content: [{ type: 'thinking', thinking: '' }] });
    await expect(adapter.analyze('x')).rejects.toThrow(/no text/);
  });

  it('throws on a refusal', async () => {
    create.mockResolvedValue({ stop_reason: 'refusal', content: [] });
    await expect(adapter.analyze('x')).rejects.toThrow(/refused/);
  });
});
