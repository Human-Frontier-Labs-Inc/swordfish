/**
 * LLM Provider Abstraction Layer
 * Supports multiple LLM providers for email threat analysis
 */

// TODO: Import when ready to test Gemini integration
// import { GoogleGenAI } from '@google/genai';
import Anthropic from '@anthropic-ai/sdk';

/**
 * Structured result from LLM analysis
 */
export interface LLMAnalysisResult {
  verdict: 'safe' | 'suspicious' | 'likely_phishing' | 'phishing' | 'likely_bec' | 'bec';
  confidence: number;
  threatType?: 'none' | 'phishing' | 'bec' | 'malware' | 'spam';
  signals: Array<{
    type: string;
    severity: 'info' | 'warning' | 'critical';
    detail: string;
  }>;
  explanation: string;
  recommendation: string;
}

/**
 * Provider-agnostic interface for LLM text generation
 */
export interface LLMProvider {
  /** Send a prompt to the LLM and return raw text response */
  analyze(systemPrompt: string, userContent: string, maxTokens: number): Promise<string>;
}

/**
 * Anthropic Claude provider implementation
 */
export class AnthropicProvider implements LLMProvider {
  private client: Anthropic;
  private model: string;

  constructor(model: string = 'claude-3-5-haiku-20241022') {
    this.client = new Anthropic();
    this.model = model;
  }

  async analyze(systemPrompt: string, userContent: string, maxTokens: number): Promise<string> {
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: maxTokens,
      system: systemPrompt,
      messages: [
        {
          role: 'user',
          content: userContent,
        },
      ],
    });

    const textContent = response.content.find((c) => c.type === 'text');
    if (!textContent || textContent.type !== 'text') {
      throw new Error('No text response from Anthropic LLM');
    }

    return textContent.text;
  }
}

/**
 * Google Gemini provider implementation
 * TODO: Install @google/genai when ready to test
 */
export class GeminiProvider implements LLMProvider {
  // TODO: Uncomment when @google/genai is installed
  // private client: GoogleGenAI;
  private model: string;

  constructor(model: string = 'gemini-2.0-flash') {
    this.model = model;
    // TODO: Uncomment when @google/genai is installed
    // this.client = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  }

  async analyze(systemPrompt: string, userContent: string, maxTokens: number): Promise<string> {
    // TODO: Replace with actual implementation when @google/genai is installed
    // const response = await this.client.models.generateContent({
    //   model: this.model,
    //   contents: `${systemPrompt}\n\n${userContent}`,
    //   config: {
    //     maxOutputTokens: maxTokens,
    //     responseMimeType: 'application/json',
    //   },
    // });
    // return response.text ?? '';

    void this.model;
    void maxTokens;
    void systemPrompt;
    void userContent;
    throw new Error(
      'GeminiProvider is not yet available. Install @google/genai and uncomment the implementation.'
    );
  }
}

export type LLMProviderName = 'anthropic' | 'gemini';

/**
 * Factory function to create an LLM provider based on configuration
 */
export function createLLMProvider(
  provider?: LLMProviderName,
  model?: string
): LLMProvider {
  const resolvedProvider = provider || (process.env.LLM_PROVIDER as LLMProviderName) || 'anthropic';

  switch (resolvedProvider) {
    case 'anthropic':
      return new AnthropicProvider(model);
    case 'gemini':
      return new GeminiProvider(model);
    default: {
      const exhaustiveCheck: never = resolvedProvider;
      throw new Error(`Unknown LLM provider: ${exhaustiveCheck}`);
    }
  }
}
