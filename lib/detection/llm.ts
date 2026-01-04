/**
 * LLM Analysis Layer
 * Uses Claude Haiku for nuanced phishing detection on edge cases
 */

import Anthropic from '@anthropic-ai/sdk';
import type { ParsedEmail, Signal, LayerResult } from './types';

const anthropic = new Anthropic();

// System prompt for phishing analysis
const SYSTEM_PROMPT = `You are an expert email security analyst specializing in phishing detection. Your task is to analyze emails and identify potential phishing attempts, social engineering tactics, and malicious content.

Analyze the provided email and return a JSON response with:
1. verdict: "safe" | "suspicious" | "likely_phishing" | "phishing"
2. confidence: 0.0-1.0 (your confidence in the verdict)
3. signals: array of detected issues, each with:
   - type: category of issue
   - severity: "info" | "warning" | "critical"
   - detail: explanation
4. explanation: 2-3 sentence summary for the end user
5. recommendation: what the recipient should do

Consider:
- Sender legitimacy (domain, display name)
- Urgency tactics and pressure language
- Requests for sensitive information
- Suspicious links or attachments
- Brand impersonation attempts
- Grammar and formatting anomalies
- Context incongruencies

Be thorough but avoid false positives. Legitimate business emails may have some urgency.`;

interface LLMAnalysisResult {
  verdict: 'safe' | 'suspicious' | 'likely_phishing' | 'phishing';
  confidence: number;
  signals: Array<{
    type: string;
    severity: 'info' | 'warning' | 'critical';
    detail: string;
  }>;
  explanation: string;
  recommendation: string;
}

/**
 * Run LLM analysis on an email
 */
export async function runLLMAnalysis(
  email: ParsedEmail,
  priorSignals: Signal[] = []
): Promise<LayerResult> {
  const startTime = performance.now();

  try {
    // Format email for analysis
    const emailContent = formatEmailForAnalysis(email, priorSignals);

    const response = await anthropic.messages.create({
      model: 'claude-3-5-haiku-20241022',
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      messages: [
        {
          role: 'user',
          content: emailContent,
        },
      ],
    });

    // Extract text content
    const textContent = response.content.find((c) => c.type === 'text');
    if (!textContent || textContent.type !== 'text') {
      throw new Error('No text response from LLM');
    }

    // Parse JSON response
    const analysis = parseAnalysisResponse(textContent.text);
    const signals = convertToSignals(analysis);

    // Calculate score based on verdict
    const score = verdictToScore(analysis.verdict);

    return {
      layer: 'llm',
      score,
      confidence: analysis.confidence,
      signals,
      processingTimeMs: performance.now() - startTime,
    };
  } catch (error) {
    console.error('LLM analysis failed:', error);

    return {
      layer: 'llm',
      score: 0,
      confidence: 0,
      signals: [],
      processingTimeMs: performance.now() - startTime,
      skipped: true,
      skipReason: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Format email content for LLM analysis
 */
function formatEmailForAnalysis(email: ParsedEmail, priorSignals: Signal[]): string {
  const parts: string[] = [];

  parts.push('=== EMAIL TO ANALYZE ===\n');

  // Headers
  parts.push(`From: ${email.from.displayName ? `"${email.from.displayName}" <${email.from.address}>` : email.from.address}`);
  parts.push(`To: ${email.to.map((t) => t.address).join(', ')}`);
  parts.push(`Subject: ${email.subject}`);
  parts.push(`Date: ${email.date.toISOString()}`);

  if (email.replyTo) {
    parts.push(`Reply-To: ${email.replyTo.address}`);
  }

  parts.push('');

  // Body
  parts.push('=== EMAIL BODY ===');
  const body = email.body.text || stripHtml(email.body.html || '');
  // Truncate very long bodies
  const truncatedBody = body.length > 3000 ? body.substring(0, 3000) + '\n[... truncated ...]' : body;
  parts.push(truncatedBody);

  // Attachments
  if (email.attachments.length > 0) {
    parts.push('\n=== ATTACHMENTS ===');
    for (const att of email.attachments) {
      parts.push(`- ${att.filename} (${att.contentType}, ${formatBytes(att.size)})`);
    }
  }

  // Prior signals from deterministic analysis
  if (priorSignals.length > 0) {
    parts.push('\n=== PRIOR ANALYSIS SIGNALS ===');
    for (const signal of priorSignals) {
      parts.push(`- [${signal.severity.toUpperCase()}] ${signal.type}: ${signal.detail}`);
    }
  }

  parts.push('\n=== END EMAIL ===');
  parts.push('\nAnalyze this email for phishing indicators. Return your analysis as JSON.');

  return parts.join('\n');
}

/**
 * Parse LLM response into structured analysis
 */
function parseAnalysisResponse(text: string): LLMAnalysisResult {
  // Try to extract JSON from the response
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    throw new Error('No JSON found in LLM response');
  }

  try {
    const parsed = JSON.parse(jsonMatch[0]);

    // Validate required fields
    if (!parsed.verdict || !['safe', 'suspicious', 'likely_phishing', 'phishing'].includes(parsed.verdict)) {
      parsed.verdict = 'suspicious';
    }

    if (typeof parsed.confidence !== 'number' || parsed.confidence < 0 || parsed.confidence > 1) {
      parsed.confidence = 0.5;
    }

    if (!Array.isArray(parsed.signals)) {
      parsed.signals = [];
    }

    return {
      verdict: parsed.verdict,
      confidence: parsed.confidence,
      signals: parsed.signals,
      explanation: parsed.explanation || 'Analysis complete.',
      recommendation: parsed.recommendation || 'Review this email carefully.',
    };
  } catch {
    throw new Error('Failed to parse LLM JSON response');
  }
}

/**
 * Convert LLM signals to standard Signal format
 */
function convertToSignals(analysis: LLMAnalysisResult): Signal[] {
  const signals: Signal[] = [];

  // Add overall LLM verdict as a signal
  signals.push({
    type: 'llm_suspicious',
    severity: analysis.verdict === 'phishing' || analysis.verdict === 'likely_phishing' ? 'critical' : analysis.verdict === 'suspicious' ? 'warning' : 'info',
    score: verdictToScore(analysis.verdict),
    detail: analysis.explanation,
    metadata: {
      recommendation: analysis.recommendation,
      llmConfidence: analysis.confidence,
    },
  });

  // Add individual signals from LLM
  for (const sig of analysis.signals) {
    const severity = sig.severity || 'warning';
    signals.push({
      type: 'llm_suspicious',
      severity,
      score: severity === 'critical' ? 15 : severity === 'warning' ? 10 : 5,
      detail: `${sig.type}: ${sig.detail}`,
    });
  }

  return signals;
}

/**
 * Convert verdict to score
 */
function verdictToScore(verdict: LLMAnalysisResult['verdict']): number {
  switch (verdict) {
    case 'phishing':
      return 50;
    case 'likely_phishing':
      return 35;
    case 'suspicious':
      return 20;
    case 'safe':
      return 0;
    default:
      return 15;
  }
}

/**
 * Strip HTML tags
 */
function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * Format bytes to human readable
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

/**
 * Check if LLM analysis should be invoked based on prior confidence
 */
export function shouldInvokeLLM(
  deterministicScore: number,
  mlConfidence: number,
  config: { invokeLlmConfidenceRange: [number, number] }
): boolean {
  const [minConfidence, maxConfidence] = config.invokeLlmConfidenceRange;

  // Invoke LLM when:
  // 1. Deterministic score is in the uncertain middle range (30-70)
  // 2. ML confidence is in the uncertain range
  const isUncertainScore = deterministicScore >= 30 && deterministicScore <= 70;
  const isUncertainConfidence = mlConfidence >= minConfidence && mlConfidence <= maxConfidence;

  return isUncertainScore || isUncertainConfidence;
}
