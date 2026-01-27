/**
 * LLM Analysis Layer
 * Uses Claude Haiku for nuanced phishing detection on edge cases
 */

import Anthropic from '@anthropic-ai/sdk';
import type { ParsedEmail, Signal, LayerResult, EmailClassificationResult } from './types';

/**
 * Phase 4: Enhanced context for LLM analysis
 */
export interface LLMAnalysisContext {
  // Phase 1: Sender reputation
  senderReputation?: {
    isKnownGood: boolean;
    trustScore: number;
    historicalActivity: string;
    knownCategories: string[];
  };

  // Phase 2: URL classification
  urlContext?: {
    totalURLs: number;
    trackingURLs: number;
    maliciousURLs: number;
    suspiciousURLs: number;
    urlTrustLevel: 'high' | 'medium' | 'low' | 'untrusted';
  };

  // Email classification
  emailClassification?: EmailClassificationResult;

  // Prior scores
  priorScores?: {
    deterministic: number;
    reputation: number;
    ml: number;
    bec: number;
  };
}

const anthropic = new Anthropic();

/**
 * Phase 4: Enhanced system prompt with context-awareness and threat calibration
 */
const SYSTEM_PROMPT = `You are an expert email security analyst specializing in phishing and Business Email Compromise (BEC) detection. Your analysis is part of a multi-layer detection pipeline that has already performed sender reputation checks, URL classification, and deterministic rule analysis.

## Response Format

Return a JSON response with:
1. **verdict**: "safe" | "suspicious" | "likely_phishing" | "phishing" | "likely_bec" | "bec"
2. **confidence**: 0.0-1.0 (your confidence in the verdict)
3. **threatType**: "none" | "phishing" | "bec" | "malware" | "spam"
4. **signals**: array of detected issues, each with:
   - type: category of issue
   - severity: "info" | "warning" | "critical"
   - detail: specific explanation
5. **explanation**: Detailed threat analysis with evidence (see format below)
6. **recommendation**: Actionable next steps (see format below)

## Threat Score Calibration

Align your analysis with these pipeline thresholds:
- **PASS (<35 points)**: Safe emails, known senders, legitimate business
- **SUSPICIOUS (55-72 points)**: Needs manual review, uncertain indicators
- **QUARANTINE (73-84 points)**: Likely threat, strong evidence required
- **BLOCK (85+ points)**: Confirmed threat, immediate action needed

Your verdict should reflect:
- **safe**: 0 points (clearly legitimate)
- **suspicious**: 20 points (minor concerns, needs review)
- **likely_phishing**: 35 points (probable phishing attempt)
- **phishing**: 50 points (confirmed phishing)
- **likely_bec**: 40 points (probable BEC attack)
- **bec**: 55 points (confirmed BEC attack)

## Context-Aware Analysis

**Sender Reputation Context:**
- If sender is "known good" with high trust score (>70), require STRONGER evidence of malice
- If sender is "first contact" + impersonation, treat as CRITICAL threat
- Known categories (marketing/transactional) expect certain patterns

**URL Classification Context:**
- If URLs are "tracking" with "high trust", this is NORMAL for marketing/newsletters
- If URLs are "malicious" or "suspicious", this AMPLIFIES threat score
- High tracking URL count from known sender = likely legitimate bulk email

**Email Classification Context:**
- "Marketing" emails: Expect urgency language ("Limited time!", "Act now!") - NOT malicious
- "Transactional" emails: Expect financial language (invoices, receipts) - NOT malicious
- "Personal" emails: Unexpected financial requests = CRITICAL BEC indicator
- "Unknown" from free provider + executive name = CRITICAL impersonation risk

## BEC Attack Sophistication Levels

**Level 1 - Basic (likely_bec):**
- Display name spoofing only
- Generic urgency without financial request

**Level 2 - Intermediate (likely_bec):**
- Domain lookalike + urgency
- Free email provider + executive title
- Reply-to mismatch + authority language

**Level 3 - Advanced (bec):**
- Compound attack: Urgency + Secrecy + Financial request
- Executive impersonation + wire transfer request
- Authority manipulation + "don't tell anyone"

**Level 4 - Critical (bec):**
- Known executive impersonation (from context) + financial request
- First contact + multi-pattern compound attack
- Sophisticated social engineering with time pressure

## BEC Attack Patterns

**Wire Transfer Fraud (CRITICAL):**
- Requests to wire money, transfer funds, change bank details
- Urgency around payment deadlines ("Today only", "Before COB")
- New banking/routing information
- Secrecy instructions ("Keep this confidential", "Don't discuss with finance")

**Gift Card Scams (CRITICAL):**
- Requests to purchase gift cards (iTunes, Amazon, Google Play, etc.)
- Instructions to send card numbers/PINs via email/text
- Unusual purchase requests from leadership
- Urgency + gift card = strong BEC indicator

**Invoice Fraud (HIGH RISK):**
- Updated invoice with new payment details
- Vendor account change requests
- Payment redirect instructions
- "Bank account updated" without verification process

**Payroll Diversion (HIGH RISK):**
- Direct deposit change requests
- W-2/tax form requests to external email
- Salary/payroll modifications without HR involvement

**Executive Impersonation (CRITICAL):**
- Display name matches executive but email domain doesn't
- CEO/CFO making unusual requests outside normal channels
- Authority pressure combined with secrecy ("Board approved this")
- "Don't tell anyone" or "Keep this between us"

## False Positive Prevention

**Legitimate Urgency (NOT malicious):**
- Marketing emails: "Sale ends tonight!", "Last chance!"
- Transactional: "Your invoice is due", "Payment reminder"
- Known sender + urgency + no financial request = likely safe

**Legitimate Financial Language (NOT malicious):**
- Transactional emails from known vendors
- Regular invoices/receipts from established relationships
- Automated payment reminders with verification links

**Do NOT penalize these patterns if sender is known good:**
- Tracking URLs in marketing emails (normal for legitimate senders)
- Multiple links in newsletters (common pattern)
- Urgency language in sales/marketing (standard practice)
- Redirect URLs from known tracking domains

## Explanation Format

Structure your explanation to be specific and evidence-based:

**For CRITICAL threats (bec/phishing):**
Format: "[THREAT TYPE] DETECTED (Confidence: [High/Medium]): [Primary evidence]. [Supporting evidence]. [Context that confirms threat]."

Example: "BEC ATTACK DETECTED (Confidence: High): Email impersonates CEO John Smith from free Gmail account (john.smith.ceo@gmail.com vs legitimate @company.com). Requests urgent wire transfer of $50,000 with secrecy instructions ('don't tell finance'). Combines 3 critical BEC patterns: executive impersonation + financial request + secrecy manipulation."

**For SUSPICIOUS threats:**
Format: "[Concern description]. [Evidence]. [Why manual review needed]."

Example: "Display name spoofing detected. Sender claims to be 'IT Support' but email is from external domain. Requests password reset via suspicious link. While not confirmed malicious, several phishing indicators present."

**For SAFE emails:**
Format: "Legitimate [email type]. [Context supporting safety]."

Example: "Legitimate marketing email from known sender Quora (trusted domain, high sender reputation). Contains tracking URLs which are normal for newsletters. Urgency language ('Don't miss these answers') is standard marketing practice, not malicious."

## Recommendation Format

Provide clear, actionable guidance:

**For BLOCK threshold threats (85+):**
"🚨 IMMEDIATE ACTION REQUIRED:
1. DO NOT [specific dangerous action]
2. Verify sender through [specific trusted method]
3. Forward to [security contact]
4. Report to [team]

Why: [Brief threat explanation]"

**For QUARANTINE threats (73-84):**
"⚠️ VERIFICATION REQUIRED:
1. Independently verify this request through [known channel]
2. Do not click any links or attachments
3. Contact sender via [trusted method]

Why: [Suspicious indicators]"

**For SUSPICIOUS threats (55-72):**
"📋 MANUAL REVIEW RECOMMENDED:
Check these indicators:
- [Specific red flag 1]
- [Specific red flag 2]
If unsure, contact [security team]."

**For PASS:**
Brief note only if any minor concerns worth noting.

## Analysis Approach

1. **Review Context First**: Check sender reputation, URL classification, email type
2. **Assess Primary Threat**: Is this BEC, phishing, malware, spam, or safe?
3. **Evaluate Evidence**: What specific indicators support your assessment?
4. **Consider False Positives**: Does context explain apparently suspicious patterns?
5. **Calibrate Severity**: Does evidence warrant the threat level you're assigning?
6. **Provide Clarity**: Make explanation specific, actionable, and context-aware

Be thorough but context-aware. Not all urgency is malicious. Not all tracking URLs are threats. Use the provided context to distinguish legitimate business communication from attacks.`;

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
 * Phase 4: Now accepts context from Phase 1-3 for better analysis
 */
export async function runLLMAnalysis(
  email: ParsedEmail,
  priorSignals: Signal[] = [],
  context?: LLMAnalysisContext
): Promise<LayerResult> {
  const startTime = performance.now();

  try {
    // Format email for analysis with Phase 1-3 context
    const emailContent = formatEmailForAnalysis(email, priorSignals, context);

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
 * Phase 4: Enhanced with Phase 1-3 context
 */
function formatEmailForAnalysis(email: ParsedEmail, priorSignals: Signal[], context?: LLMAnalysisContext): string {
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

  // Phase 4: Add context summary
  if (context) {
    parts.push('=== CONTEXT FROM PRIOR ANALYSIS ===');

    // Sender reputation (Phase 1)
    if (context.senderReputation) {
      const rep = context.senderReputation;
      parts.push(`\n**Sender Reputation:**`);
      parts.push(`- Status: ${rep.isKnownGood ? 'KNOWN GOOD SENDER' : 'Unknown/New sender'}`);
      parts.push(`- Trust Score: ${rep.trustScore}/100`);
      parts.push(`- Historical Activity: ${rep.historicalActivity}`);
      if (rep.knownCategories.length > 0) {
        parts.push(`- Known Categories: ${rep.knownCategories.join(', ')}`);
      }
    }

    // URL classification (Phase 2)
    if (context.urlContext) {
      const urls = context.urlContext;
      parts.push(`\n**URL Analysis:**`);
      parts.push(`- Total URLs: ${urls.totalURLs}`);
      parts.push(`- Tracking URLs: ${urls.trackingURLs} (legitimate tracking)`);
      parts.push(`- Suspicious URLs: ${urls.suspiciousURLs}`);
      parts.push(`- Malicious URLs: ${urls.maliciousURLs}`);
      parts.push(`- Overall Trust Level: ${urls.urlTrustLevel}`);
    }

    // Email classification
    if (context.emailClassification) {
      const email = context.emailClassification;
      parts.push(`\n**Email Classification:**`);
      parts.push(`- Type: ${email.type.toUpperCase()}`);
      parts.push(`- Known Sender: ${email.isKnownSender ? 'Yes' : 'No'}`);
      parts.push(`- Confidence: ${(email.confidence * 100).toFixed(1)}%`);
      if (email.senderCategory) {
        parts.push(`- Category: ${email.senderCategory}`);
      }
    }

    // Prior scores
    if (context.priorScores) {
      const scores = context.priorScores;
      parts.push(`\n**Prior Detection Scores:**`);
      parts.push(`- Deterministic Layer: ${scores.deterministic}/100`);
      parts.push(`- Reputation Layer: ${scores.reputation}/100`);
      parts.push(`- ML Layer: ${scores.ml}/100`);
      parts.push(`- BEC Layer: ${scores.bec}/100`);
    }

    parts.push('\n---');
  }

  // Body
  parts.push('\n=== EMAIL BODY ===');
  const body = email.body.text || stripHtml(email.body.html || '');
  // Truncate very long bodies
  const truncatedBody = body.length > 2500 ? body.substring(0, 2500) + '\n[... truncated ...]' : body;
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
    parts.push('\n=== SPECIFIC THREAT INDICATORS DETECTED ===');
    const criticalSignals = priorSignals.filter(s => s.severity === 'critical');
    const warningSignals = priorSignals.filter(s => s.severity === 'warning');
    const infoSignals = priorSignals.filter(s => s.severity === 'info');

    if (criticalSignals.length > 0) {
      parts.push(`\n**CRITICAL Signals (${criticalSignals.length}):**`);
      for (const signal of criticalSignals) {
        parts.push(`- ${signal.type}: ${signal.detail}`);
      }
    }

    if (warningSignals.length > 0) {
      parts.push(`\n**WARNING Signals (${warningSignals.length}):**`);
      for (const signal of warningSignals) {
        parts.push(`- ${signal.type}: ${signal.detail}`);
      }
    }

    if (infoSignals.length > 0 && infoSignals.length <= 5) {
      parts.push(`\n**INFO Signals (${infoSignals.length}):**`);
      for (const signal of infoSignals) {
        parts.push(`- ${signal.type}: ${signal.detail}`);
      }
    }
  }

  parts.push('\n=== END EMAIL ===');
  parts.push('\nBased on the email content AND the context provided above, analyze for phishing and BEC threats.');
  parts.push('Use the context to make an informed decision about false positives vs real threats.');
  parts.push('Return your analysis as JSON with the specified format.');

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
