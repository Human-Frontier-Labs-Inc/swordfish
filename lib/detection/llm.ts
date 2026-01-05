/**
 * LLM Analysis Layer
 * Uses Claude Haiku for nuanced phishing detection on edge cases
 */

import Anthropic from '@anthropic-ai/sdk';
import type { ParsedEmail, Signal, LayerResult } from './types';

const anthropic = new Anthropic();

// System prompt for phishing and BEC analysis
const SYSTEM_PROMPT = `You are an expert email security analyst specializing in phishing and Business Email Compromise (BEC) detection. Your task is to analyze emails and identify potential threats including phishing attempts, BEC attacks, social engineering tactics, and malicious content.

Analyze the provided email and return a JSON response with:
1. verdict: "safe" | "suspicious" | "likely_phishing" | "phishing" | "likely_bec" | "bec"
2. confidence: 0.0-1.0 (your confidence in the verdict)
3. threatType: "none" | "phishing" | "bec" | "malware" | "spam" (primary threat classification)
4. signals: array of detected issues, each with:
   - type: category of issue
   - severity: "info" | "warning" | "critical"
   - detail: explanation
5. explanation: 2-3 sentence summary for the end user
6. recommendation: what the recipient should do

## BEC Attack Patterns to Detect:

**Wire Transfer Fraud:**
- Requests to wire money, transfer funds, change bank details
- Urgency around payment deadlines
- New banking/routing information

**Gift Card Scams:**
- Requests to purchase gift cards (iTunes, Amazon, Google Play)
- Instructions to send card numbers/PINs
- Unusual purchase requests from leadership

**Invoice Fraud:**
- Updated invoice with new payment details
- Vendor account change requests
- Payment redirect instructions

**Payroll Diversion:**
- Direct deposit change requests
- W-2/tax form requests
- Salary/payroll modifications

**Executive Impersonation:**
- Display name matches executive but email doesn't
- CEO/CFO making unusual requests
- Authority pressure combined with secrecy
- "Don't tell anyone" or "Keep this between us"

## Key BEC Indicators:
- Display name spoofing (executive name, wrong domain)
- Free email domains with executive names
- Reply-to address mismatch
- Urgency + financial request combination
- Secrecy requests
- Authority/trust manipulation
- Unusual requests from leadership

## Also Consider:
- Sender legitimacy (domain, display name)
- Urgency tactics and pressure language
- Requests for sensitive information
- Suspicious links or attachments
- Brand impersonation attempts
- Grammar and formatting anomalies
- Context incongruencies

Be thorough but avoid false positives. BEC attacks often have good grammar and appear legitimate.`;

interface LLMAnalysisResult {
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
  parts.push('\nAnalyze this email for phishing AND Business Email Compromise (BEC) indicators. Return your analysis as JSON.');

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
    if (!parsed.verdict || !['safe', 'suspicious', 'likely_phishing', 'phishing', 'likely_bec', 'bec'].includes(parsed.verdict)) {
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
      threatType: parsed.threatType,
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

  // Determine signal type based on verdict
  const isBEC = analysis.verdict === 'bec' || analysis.verdict === 'likely_bec' || analysis.threatType === 'bec';
  const isPhishing = analysis.verdict === 'phishing' || analysis.verdict === 'likely_phishing' || analysis.threatType === 'phishing';
  const isCritical = analysis.verdict === 'phishing' || analysis.verdict === 'bec' || analysis.verdict === 'likely_phishing' || analysis.verdict === 'likely_bec';

  // Add overall LLM verdict as a signal
  signals.push({
    type: isBEC ? 'llm_bec_detected' : isPhishing ? 'llm_phishing_detected' : 'llm_analysis',
    severity: isCritical ? 'critical' : analysis.verdict === 'suspicious' ? 'warning' : 'info',
    score: verdictToScore(analysis.verdict),
    detail: analysis.explanation,
    metadata: {
      recommendation: analysis.recommendation,
      llmConfidence: analysis.confidence,
      threatType: analysis.threatType,
    },
  });

  // Add individual signals from LLM
  for (const sig of analysis.signals) {
    const severity = sig.severity || 'warning';
    // Determine signal type from content
    const sigType = sig.type.toLowerCase();
    let signalType: 'llm_suspicious' | 'llm_bec_indicator' | 'llm_phishing_indicator' = 'llm_suspicious';
    if (sigType.includes('bec') || sigType.includes('wire') || sigType.includes('gift_card') || sigType.includes('impersonation')) {
      signalType = 'llm_bec_indicator';
    } else if (sigType.includes('phishing') || sigType.includes('credential')) {
      signalType = 'llm_phishing_indicator';
    }

    signals.push({
      type: signalType,
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
    case 'bec':
      return 55; // BEC often more targeted/dangerous
    case 'likely_phishing':
      return 35;
    case 'likely_bec':
      return 40;
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
