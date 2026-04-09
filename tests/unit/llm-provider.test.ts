/**
 * Unit tests for LLM provider abstraction
 * Tests factory function and provider implementations
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the Anthropic SDK
const mockCreate = vi.fn();
vi.mock('@anthropic-ai/sdk', () => {
  return {
    default: vi.fn().mockImplementation(() => ({
      messages: {
        create: mockCreate,
      },
    })),
  };
});

import {
  createLLMProvider,
  AnthropicProvider,
  GeminiProvider,
} from '@/lib/detection/llm-provider';

describe('createLLMProvider', () => {
  const originalEnv = process.env.LLM_PROVIDER;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.LLM_PROVIDER;
  });

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.LLM_PROVIDER = originalEnv;
    } else {
      delete process.env.LLM_PROVIDER;
    }
  });

  it('should return AnthropicProvider by default', () => {
    const provider = createLLMProvider();
    expect(provider).toBeInstanceOf(AnthropicProvider);
  });

  it('should return AnthropicProvider when explicitly specified', () => {
    const provider = createLLMProvider('anthropic');
    expect(provider).toBeInstanceOf(AnthropicProvider);
  });

  it('should return GeminiProvider when LLM_PROVIDER=gemini', () => {
    process.env.LLM_PROVIDER = 'gemini';
    const provider = createLLMProvider();
    expect(provider).toBeInstanceOf(GeminiProvider);
  });

  it('should return GeminiProvider when explicitly specified', () => {
    const provider = createLLMProvider('gemini');
    expect(provider).toBeInstanceOf(GeminiProvider);
  });

  it('should prefer explicit argument over env var', () => {
    process.env.LLM_PROVIDER = 'gemini';
    const provider = createLLMProvider('anthropic');
    expect(provider).toBeInstanceOf(AnthropicProvider);
  });
});

describe('AnthropicProvider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should call the Anthropic SDK messages.create with correct params', async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: 'text', text: '{"verdict":"safe"}' }],
    });

    const provider = new AnthropicProvider('claude-3-5-haiku-20241022');
    const result = await provider.analyze('system prompt', 'user content', 1024);

    expect(result).toBe('{"verdict":"safe"}');
    expect(mockCreate).toHaveBeenCalledWith({
      model: 'claude-3-5-haiku-20241022',
      max_tokens: 1024,
      system: 'system prompt',
      messages: [
        {
          role: 'user',
          content: 'user content',
        },
      ],
    });
  });

  it('should throw when no text response is returned', async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: 'tool_use', id: 'tool-1', name: 'fn', input: {} }],
    });

    const provider = new AnthropicProvider();
    await expect(
      provider.analyze('sys', 'user', 100)
    ).rejects.toThrow('No text response from Anthropic LLM');
  });
});

describe('GeminiProvider', () => {
  it('should throw because it is not yet implemented', async () => {
    const provider = new GeminiProvider();
    await expect(
      provider.analyze('sys', 'user', 100)
    ).rejects.toThrow('GeminiProvider is not yet available');
  });
});
