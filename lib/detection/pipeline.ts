/**
 * Main Detection Pipeline
 * Orchestrates all detection layers and produces final verdicts
 */

import type {
  ParsedEmail,
  EmailVerdict,
  LayerResult,
  Signal,
  DetectionConfig,
} from './types';
import { DEFAULT_DETECTION_CONFIG } from './types';
import { runDeterministicAnalysis } from './deterministic';
import { runLLMAnalysis, shouldInvokeLLM } from './llm';
import { evaluatePolicies } from '@/lib/policies/engine';
import { classifyEmail } from './ml/classifier';
import { checkReputation } from './reputation/service';
import { detectBEC, quickBECCheck, type BECSignal } from './bec';
import {
  classifyEmailType,
  isLegitimateReplyTo,
  type EmailClassification,
} from './classifier';
import {
  runEnhancedReputationLookup,
  filterDeterministicSignalsWithReputation,
  calculateScoreWithTrust,
  type EnhancedReputationContext,
} from './reputation/sender-lookup';

/**
 * Main detection pipeline - analyzes an email through all layers
 */
export async function analyzeEmail(
  email: ParsedEmail,
  tenantId: string,
  configOverrides: Partial<DetectionConfig> = {}
): Promise<EmailVerdict> {
  const config: DetectionConfig = { ...DEFAULT_DETECTION_CONFIG, ...configOverrides };
  const startTime = performance.now();
  const layerResults: LayerResult[] = [];
  const allSignals: Signal[] = [];
  let llmTokensUsed = 0;
  let reputationContext: EnhancedReputationContext | null = null;

  // Layer 0: Email Type Classification (NEW - runs first)
  // This classifies the email type BEFORE threat detection
  let emailClassification: EmailClassification | null = null;
  try {
    emailClassification = await classifyEmailType(email);

    // Add classification signal for transparency
    if (emailClassification.isKnownSender) {
      allSignals.push({
        type: 'classification',
        severity: 'info',
        score: 0,
        detail: `Known sender: ${emailClassification.senderInfo?.name} (${emailClassification.type})`,
      });
    } else if (emailClassification.isLikelyMarketing) {
      allSignals.push({
        type: 'classification',
        severity: 'info',
        score: 0,
        detail: `Detected as marketing email (${Math.round(emailClassification.confidence * 100)}% confidence)`,
      });
    }
  } catch (error) {
    console.error('Email classification error:', error);
    // Continue without classification
  }

  // Layer 1: Policy Evaluation (allowlists/blocklists)
  try {
    const policyResult = await evaluatePolicies(email, tenantId);

    if (policyResult.matched) {
      // Short-circuit based on policy
      if (policyResult.action === 'allow') {
        // Allowlisted sender - skip all detection
        return {
          messageId: email.messageId,
          tenantId,
          verdict: 'pass',
          overallScore: 0,
          confidence: 1.0,
          signals: [{
            type: 'policy',
            severity: 'info',
            score: 0,
            detail: policyResult.reason || 'Sender is in allowlist',
          }],
          layerResults: [],
          explanation: 'This email was allowed by policy.',
          recommendation: 'Sender is on your allowlist.',
          processingTimeMs: performance.now() - startTime,
          analyzedAt: new Date(),
          policyApplied: {
            policyId: policyResult.policyId,
            policyName: policyResult.policyName,
            action: policyResult.action,
          },
        };
      } else if (policyResult.action === 'block') {
        // Blocklisted sender - block immediately
        return {
          messageId: email.messageId,
          tenantId,
          verdict: 'block',
          overallScore: 100,
          confidence: 1.0,
          signals: [{
            type: 'policy',
            severity: 'critical',
            score: 100,
            detail: policyResult.reason || 'Sender is in blocklist',
          }],
          layerResults: [],
          explanation: 'This email was blocked by policy.',
          recommendation: 'Sender is on your blocklist.',
          processingTimeMs: performance.now() - startTime,
          analyzedAt: new Date(),
          policyApplied: {
            policyId: policyResult.policyId,
            policyName: policyResult.policyName,
            action: policyResult.action,
          },
        };
      }
      // Other actions (quarantine, tag) - continue with detection but note the policy
      allSignals.push({
        type: 'policy',
        severity: 'info',
        score: 0,
        detail: `Policy "${policyResult.policyName}" matched: ${policyResult.reason}`,
      });
    }
  } catch (error) {
    // Log but don't fail if policy evaluation fails
    console.error('Policy evaluation error:', error);
  }

  // Layer 2: Deterministic Analysis (always runs)
  const deterministicResult = await runDeterministicAnalysis(email);

  // Layer 3: Enhanced Reputation Lookup (runs before filtering deterministic signals)
  const { result: reputationResult, context: repContext } = await runEnhancedReputationLookup(email);
  reputationContext = repContext;
  layerResults.push(reputationResult);
  allSignals.push(...reputationResult.signals);

  // Filter out false positives based on email classification AND sender reputation
  let filteredDeterministicSignals = filterSignalsForEmailType(
    deterministicResult.signals,
    emailClassification
  );

  // Apply reputation-based filtering to remove known tracking URL false positives
  if (reputationContext && reputationContext.isKnownSender) {
    filteredDeterministicSignals = filterDeterministicSignalsWithReputation(
      filteredDeterministicSignals,
      reputationContext
    );
  }

  const filteredDeterministicResult = {
    ...deterministicResult,
    signals: filteredDeterministicSignals,
    score: recalculateLayerScore(filteredDeterministicSignals),
  };
  layerResults.push(filteredDeterministicResult);
  allSignals.push(...filteredDeterministicSignals);

  // Layer 4: ML Analysis
  const mlResult = await runMLAnalysis(email, allSignals);

  // Filter ML signals for email type
  const filteredMLSignals = filterSignalsForEmailType(
    mlResult.signals,
    emailClassification
  );
  const filteredMLResult = {
    ...mlResult,
    signals: filteredMLSignals,
    score: recalculateLayerScore(filteredMLSignals),
  };
  layerResults.push(filteredMLResult);
  allSignals.push(...filteredMLSignals);

  // Layer 5: BEC Detection (Business Email Compromise)
  // Skip BEC detection for marketing/transactional emails from known senders
  let becResult: LayerResult;
  if (emailClassification?.skipBECDetection && emailClassification.isKnownSender) {
    becResult = {
      layer: 'bec',
      score: 0,
      confidence: 1.0,
      signals: [],
      processingTimeMs: 0,
      skipped: true,
      skipReason: `Skipped for ${emailClassification.type} email from known sender`,
    };
  } else {
    becResult = await runBECAnalysis(email, tenantId);

    // Filter BEC signals for email type
    const filteredBECSignals = filterSignalsForEmailType(
      becResult.signals,
      emailClassification
    );
    becResult = {
      ...becResult,
      signals: filteredBECSignals,
      score: recalculateLayerScore(filteredBECSignals),
    };
  }
  layerResults.push(becResult);
  allSignals.push(...becResult.signals);

  // Layer 6: LLM Analysis (conditional - only for uncertain cases)
  // Skip LLM if explicitly disabled (e.g., for background sync to avoid timeout)
  const shouldUseLLM = !config.skipLLM && shouldInvokeLLM(
    filteredDeterministicResult.score,
    filteredMLResult.confidence,
    config
  );

  // Also invoke LLM if BEC is suspected but not confirmed
  const becSuspected = becResult.score >= 30 && becResult.confidence < 0.8;

  if (shouldUseLLM || becSuspected) {
    const llmResult = await runLLMAnalysis(email, allSignals);
    layerResults.push(llmResult);
    allSignals.push(...llmResult.signals);
    // Estimate tokens used (rough approximation)
    llmTokensUsed = estimateTokensUsed(email);
  } else {
    layerResults.push({
      layer: 'llm',
      score: 0,
      confidence: 0,
      signals: [],
      processingTimeMs: 0,
      skipped: true,
      skipReason: config.skipLLM
        ? 'Skipped for background sync (timeout optimization)'
        : 'Not needed - sufficient confidence from prior layers',
    });
  }

  // Layer 7: Sandbox (TODO - for attachments, placeholder for now)
  const sandboxResult = await runSandboxAnalysis(email);
  layerResults.push(sandboxResult);
  allSignals.push(...sandboxResult.signals);

  // Calculate final score and verdict
  let { overallScore, confidence } = calculateFinalScore(layerResults, config);

  // Apply sender reputation trust modifier FIRST (more precise than email classification)
  if (reputationContext && reputationContext.isKnownSender && reputationContext.trustModifier < 1.0) {
    const { adjustedScore, reduction, reductionPercent } = calculateScoreWithTrust(
      overallScore,
      reputationContext
    );

    const originalScore = overallScore;
    overallScore = adjustedScore;

    // Add signal explaining sender reputation score reduction
    allSignals.push({
      type: 'sender_trust_applied',
      severity: 'info',
      score: 0,
      detail: `Score reduced by ${Math.round(reductionPercent)}% due to sender reputation (${reputationContext.senderReputation!.display_name}, trust score: ${reputationContext.senderReputation!.trust_score}/100)`,
      metadata: {
        originalScore,
        adjustedScore,
        reduction,
        reductionPercent: Math.round(reductionPercent),
        senderDomain: reputationContext.senderReputation!.domain,
        trustScore: reputationContext.senderReputation!.trust_score,
        category: reputationContext.senderReputation!.category,
      },
    });
  }
  // Apply email type modifier to final score (only if sender reputation didn't already apply)
  // Marketing/known senders get reduced threat scores
  else if (emailClassification && emailClassification.threatScoreModifier < 1.0) {
    const originalScore = overallScore;
    overallScore = Math.round(overallScore * emailClassification.threatScoreModifier);

    // Add signal explaining score reduction
    if (originalScore !== overallScore) {
      allSignals.push({
        type: 'classification',
        severity: 'info',
        score: 0,
        detail: `Score reduced from ${originalScore} to ${overallScore} (${emailClassification.type} email from ${emailClassification.isKnownSender ? 'known sender' : 'likely legitimate source'})`,
      });
    }
  }

  const verdict = determineVerdict(overallScore, config);

  // Generate explanation from signals
  const { explanation, recommendation } = generateExplanation(allSignals, verdict);

  return {
    messageId: email.messageId,
    tenantId,
    verdict,
    overallScore,
    confidence,
    signals: allSignals,
    layerResults,
    explanation,
    recommendation,
    processingTimeMs: performance.now() - startTime,
    llmTokensUsed: llmTokensUsed > 0 ? llmTokensUsed : undefined,
    analyzedAt: new Date(),
    // Include classification in result for transparency
    emailClassification: emailClassification ? {
      type: emailClassification.type,
      confidence: emailClassification.confidence,
      isKnownSender: emailClassification.isKnownSender,
      senderName: emailClassification.senderInfo?.name,
      senderCategory: emailClassification.senderInfo?.category,
      threatScoreModifier: emailClassification.threatScoreModifier,
      skipBECDetection: emailClassification.skipBECDetection,
      skipGiftCardDetection: emailClassification.skipGiftCardDetection,
      signals: emailClassification.marketingSignals?.signals || [],
    } : undefined,
  };
}

/**
 * Filter signals that are false positives for certain email types
 */
function filterSignalsForEmailType(
  signals: Signal[],
  classification: EmailClassification | null
): Signal[] {
  if (!classification) return signals;

  return signals.filter(signal => {
    // Marketing emails: Remove gift card and some BEC signals
    if (classification.skipGiftCardDetection) {
      if (signal.type === 'bec_gift_card_scam' ||
          signal.type === 'ml_financial_request' ||
          signal.detail?.toLowerCase().includes('gift card')) {
        return false;
      }
    }

    // Known senders: Remove reply-to mismatch if it's a known pattern
    if (classification.isKnownSender && classification.senderInfo) {
      if (signal.type === 'reply_to_mismatch' || signal.type === 'bec_reply_to_mismatch') {
        // Check if it's a legitimate reply-to for this sender
        const replyToDomain = extractDomainFromSignal(signal);
        if (replyToDomain && isLegitimateReplyTo(classification.senderInfo, replyToDomain)) {
          return false;
        }
      }
    }

    // Marketing emails: Reduce weight of urgency signals (sales urgency is normal)
    if (classification.isLikelyMarketing) {
      if (signal.type === 'ml_urgency' ||
          signal.type === 'bec_urgency_pressure' ||
          signal.detail?.toLowerCase().includes('urgency')) {
        // Don't remove, but we'll handle score reduction elsewhere
        return true;
      }
    }

    return true;
  });
}

/**
 * Extract domain from signal detail (for reply-to checks)
 */
function extractDomainFromSignal(signal: Signal): string | null {
  if (!signal.detail) return null;

  // Try to extract domain from patterns like "Reply-To domain (example.com)"
  const match = signal.detail.match(/\(([a-z0-9.-]+\.[a-z]+)\)/i);
  return match ? match[1] : null;
}

/**
 * Recalculate layer score from filtered signals
 */
function recalculateLayerScore(signals: Signal[]): number {
  return Math.min(100, signals.reduce((sum, s) => sum + s.score, 0));
}

/**
 * Reputation lookup using threat intelligence
 */
async function runReputationLookup(email: ParsedEmail): Promise<LayerResult> {
  const startTime = performance.now();
  const signals: Signal[] = [];

  try {
    // Extract entities to check
    const senderDomain = email.from.domain || email.from.address.split('@')[1]?.toLowerCase();
    const urls = extractURLs((email.body.text || '') + (email.body.html || ''));
    const domains = urls.map(url => {
      try {
        return new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
      } catch {
        return null;
      }
    }).filter(Boolean) as string[];

    // Add sender domain
    if (senderDomain) {
      domains.unshift(senderDomain);
    }

    // Deduplicate
    const uniqueDomains = [...new Set(domains)];
    const uniqueUrls = [...new Set(urls)];

    // Check reputation
    const reputationResult = await checkReputation({
      domains: uniqueDomains.slice(0, 10), // Limit to 10
      urls: uniqueUrls.slice(0, 10),
      emails: [email.from.address],
    });

    // Convert reputation results to signals
    for (const domainRep of reputationResult.domains) {
      if (domainRep.category === 'malicious') {
        signals.push({
          type: 'malicious_domain',
          severity: 'critical',
          score: 40,
          detail: `Malicious domain detected: ${domainRep.entity}`,
        });
      } else if (domainRep.category === 'suspicious') {
        signals.push({
          type: 'suspicious_domain',
          severity: 'warning',
          score: 20,
          detail: `Suspicious domain: ${domainRep.entity}`,
        });
      }
    }

    for (const urlRep of reputationResult.urls) {
      if (urlRep.category === 'malicious') {
        signals.push({
          type: 'malicious_url',
          severity: 'critical',
          score: 35,
          detail: `Malicious URL detected: ${urlRep.entity.substring(0, 50)}...`,
        });
      } else if (urlRep.category === 'suspicious') {
        signals.push({
          type: 'suspicious_url',
          severity: 'warning',
          score: 15,
          detail: `Suspicious URL: ${urlRep.entity.substring(0, 50)}...`,
        });
      }
    }

    for (const emailRep of reputationResult.emails) {
      if (emailRep.category === 'malicious') {
        signals.push({
          type: 'malicious_sender',
          severity: 'critical',
          score: 50,
          detail: `Known malicious sender: ${emailRep.entity}`,
        });
      } else if (emailRep.category === 'suspicious') {
        signals.push({
          type: 'suspicious_sender',
          severity: 'warning',
          score: 25,
          detail: `Suspicious sender: ${emailRep.entity}`,
        });
      }
    }

    const score = Math.min(100, signals.reduce((sum, s) => sum + s.score, 0));
    const confidence = reputationResult.domains.length > 0 || reputationResult.urls.length > 0
      ? 0.8
      : 0.5;

    return {
      layer: 'reputation',
      score,
      confidence,
      signals,
      processingTimeMs: performance.now() - startTime,
    };
  } catch (error) {
    console.error('Reputation lookup error:', error);
    return {
      layer: 'reputation',
      score: 0,
      confidence: 0.3,
      signals,
      processingTimeMs: performance.now() - startTime,
      skipped: true,
      skipReason: 'Reputation service error',
    };
  }
}

/**
 * ML Analysis using trained classifier
 */
async function runMLAnalysis(email: ParsedEmail, _priorSignals: Signal[]): Promise<LayerResult> {
  const startTime = performance.now();
  const signals: Signal[] = [];

  try {
    const prediction = await classifyEmail(email);

    // Convert ML signals to layer signals
    for (const signal of prediction.signals) {
      signals.push({
        type: signal.type,
        severity: signal.severity,
        score: signal.score,
        detail: signal.detail,
      });
    }

    // Add category-specific signals - scores scaled by confidence
    if (prediction.category === 'phishing' && prediction.confidence > 0.6) {
      // Scale score by confidence: 60% = 45, 80% = 60, 100% = 75
      const phishingScore = Math.round(45 + (prediction.confidence - 0.6) * 75);
      signals.push({
        type: 'ml_phishing_detected',
        severity: 'critical',
        score: phishingScore,
        detail: `ML classifier detected phishing (${(prediction.confidence * 100).toFixed(0)}% confidence)`,
      });
    } else if (prediction.category === 'bec' && prediction.confidence > 0.6) {
      const becScore = Math.round(50 + (prediction.confidence - 0.6) * 75);
      signals.push({
        type: 'ml_bec_detected',
        severity: 'critical',
        score: becScore,
        detail: `ML classifier detected business email compromise (${(prediction.confidence * 100).toFixed(0)}% confidence)`,
      });
    } else if (prediction.category === 'malware' && prediction.confidence > 0.6) {
      const malwareScore = Math.round(55 + (prediction.confidence - 0.6) * 75);
      signals.push({
        type: 'ml_malware_detected',
        severity: 'critical',
        score: malwareScore,
        detail: `ML classifier detected potential malware delivery (${(prediction.confidence * 100).toFixed(0)}% confidence)`,
      });
    } else if (prediction.category === 'spam' && prediction.confidence > 0.6) {
      signals.push({
        type: 'ml_spam_detected',
        severity: 'warning',
        score: 20,
        detail: `ML classifier detected spam (${(prediction.confidence * 100).toFixed(0)}% confidence)`,
      });
    }

    // Calculate layer score (weighted by confidence)
    const baseScore = prediction.score * 100;
    const weightedScore = baseScore * prediction.confidence;

    return {
      layer: 'ml',
      score: Math.min(100, Math.round(weightedScore)),
      confidence: prediction.confidence,
      signals,
      processingTimeMs: performance.now() - startTime,
      metadata: {
        category: prediction.category,
        features: prediction.features,
      },
    };
  } catch (error) {
    console.error('ML analysis error:', error);
    return {
      layer: 'ml',
      score: 0,
      confidence: 0.3,
      signals,
      processingTimeMs: performance.now() - startTime,
      skipped: true,
      skipReason: 'ML classifier error',
    };
  }
}

/**
 * Placeholder: Sandbox analysis for attachments
 */
async function runSandboxAnalysis(email: ParsedEmail): Promise<LayerResult> {
  const startTime = performance.now();
  const signals: Signal[] = [];

  // Only run if there are attachments
  if (email.attachments.length === 0) {
    return {
      layer: 'sandbox',
      score: 0,
      confidence: 1,
      signals: [],
      processingTimeMs: performance.now() - startTime,
      skipped: true,
      skipReason: 'No attachments to analyze',
    };
  }

  // TODO: Implement sandbox analysis:
  // - Static file analysis
  // - Dynamic execution in sandbox
  // - Behavior monitoring
  // - Network activity tracking

  // Check for dangerous file types
  const dangerousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.js', '.vbs', '.hta'];
  const macroExtensions = ['.docm', '.xlsm', '.pptm'];
  const archiveExtensions = ['.zip', '.rar', '.7z', '.tar', '.gz'];

  for (const attachment of email.attachments) {
    const ext = attachment.filename.toLowerCase().split('.').pop() || '';

    if (dangerousExtensions.some((d) => attachment.filename.toLowerCase().endsWith(d))) {
      signals.push({
        type: 'executable',
        severity: 'critical',
        score: 40,
        detail: `Dangerous executable attachment: ${attachment.filename}`,
      });
    }

    if (macroExtensions.some((m) => attachment.filename.toLowerCase().endsWith(m))) {
      signals.push({
        type: 'macro_enabled',
        severity: 'warning',
        score: 25,
        detail: `Macro-enabled document: ${attachment.filename}`,
      });
    }

    if (archiveExtensions.some((a) => attachment.filename.toLowerCase().endsWith(a))) {
      signals.push({
        type: 'dangerous_attachment',
        severity: 'info',
        score: 10,
        detail: `Archive file that may contain hidden threats: ${attachment.filename}`,
      });
    }
  }

  const score = signals.reduce((sum, s) => sum + s.score, 0);

  return {
    layer: 'sandbox',
    score: Math.min(100, score),
    confidence: 0.7,
    signals,
    processingTimeMs: performance.now() - startTime,
  };
}

/**
 * BEC Analysis using specialized BEC detection engine
 */
async function runBECAnalysis(email: ParsedEmail, tenantId: string): Promise<LayerResult> {
  const startTime = performance.now();
  const signals: Signal[] = [];

  try {
    // Extract sender info
    const senderEmail = typeof email.from === 'string'
      ? email.from
      : (email.from?.address || '');
    const senderDisplayName = typeof email.from === 'string'
      ? email.from
      : (email.from?.displayName || senderEmail);

    // Get organization domain from sender if available
    const orgDomain = senderEmail.split('@')[1]?.toLowerCase();

    // Run full BEC detection
    const becResult = await detectBEC(
      {
        subject: email.subject || '',
        body: email.body.text || email.body.html || '',
        senderEmail,
        senderDisplayName,
        replyTo: email.replyTo?.address,
      },
      tenantId,
      orgDomain
    );

    // Convert BEC signals to pipeline signals
    // Map BEC signal types to valid SignalType
    const mapBECSignalType = (type: string): Signal['type'] => {
      const typeMap: Record<string, Signal['type']> = {
        'wire_transfer_request': 'bec_wire_transfer_request',
        'gift_card_scam': 'bec_gift_card_scam',
        'invoice_fraud': 'bec_invoice_fraud',
        'payroll_diversion': 'bec_payroll_diversion',
        'urgency_pressure': 'bec_urgency_pressure',
        'secrecy_request': 'bec_secrecy_request',
        'authority_manipulation': 'bec_authority_manipulation',
        'compound_attack': 'bec_compound_attack',
        'financial_amount': 'bec_financial_amount',
        'display_name_spoof': 'bec_display_name_spoof',
        'title_spoof': 'bec_title_spoof',
        'domain_lookalike': 'bec_domain_lookalike',
        'reply_to_mismatch': 'bec_reply_to_mismatch',
        'unicode_spoof': 'bec_unicode_spoof',
        'cousin_domain': 'bec_cousin_domain',
        'free_email_executive': 'bec_free_email_executive',
      };
      return typeMap[type] || 'bec_detected';
    };

    for (const becSignal of becResult.signals) {
      signals.push({
        type: mapBECSignalType(becSignal.type),
        severity: becSignal.severity === 'critical' ? 'critical' :
                  becSignal.severity === 'high' ? 'critical' :
                  becSignal.severity === 'medium' ? 'warning' : 'info',
        score: becSignal.severity === 'critical' ? 35 :
               becSignal.severity === 'high' ? 25 :
               becSignal.severity === 'medium' ? 15 : 5,
        detail: becSignal.description,
        metadata: {
          category: becSignal.category,
          evidence: becSignal.evidence,
        },
      });
    }

    // Add impersonation signals
    if (becResult.impersonation?.isImpersonation) {
      signals.push({
        type: 'bec_impersonation',
        severity: 'critical',
        score: 40,
        detail: becResult.impersonation.explanation,
        metadata: {
          impersonationType: becResult.impersonation.impersonationType,
          matchedVIP: becResult.impersonation.matchedVIP?.displayName,
          confidence: becResult.impersonation.confidence,
        },
      });
    }

    // Add financial risk signals
    if (becResult.financialRisk.hasFinancialRequest && becResult.financialRisk.maxAmount > 0) {
      const riskSeverity = becResult.financialRisk.riskLevel === 'critical' ? 'critical' :
                           becResult.financialRisk.riskLevel === 'high' ? 'critical' : 'warning';
      signals.push({
        type: 'bec_financial_risk',
        severity: riskSeverity,
        score: becResult.financialRisk.riskLevel === 'critical' ? 30 :
               becResult.financialRisk.riskLevel === 'high' ? 20 : 10,
        detail: `Financial request detected: $${becResult.financialRisk.maxAmount.toLocaleString()}`,
        metadata: {
          amounts: becResult.financialRisk.amounts,
          riskLevel: becResult.financialRisk.riskLevel,
        },
      });
    }

    // Overall BEC verdict signal
    if (becResult.isBEC) {
      signals.push({
        type: 'bec_detected',
        severity: 'critical',
        score: 35,
        detail: becResult.summary,
        metadata: {
          confidence: becResult.confidence,
          riskLevel: becResult.riskLevel,
          patternCount: becResult.patterns.length,
        },
      });
    }

    // Calculate layer score
    const score = Math.min(100, Math.round(becResult.confidence * 100));

    return {
      layer: 'bec' as LayerResult['layer'],
      score: becResult.isBEC ? Math.max(score, 50) : score,
      confidence: becResult.confidence,
      signals,
      processingTimeMs: performance.now() - startTime,
      metadata: {
        isBEC: becResult.isBEC,
        riskLevel: becResult.riskLevel,
        patternCount: becResult.patterns.length,
        hasImpersonation: becResult.impersonation?.isImpersonation,
        financialRisk: becResult.financialRisk,
      },
    };
  } catch (error) {
    console.error('BEC analysis error:', error);
    return {
      layer: 'bec' as LayerResult['layer'],
      score: 0,
      confidence: 0.3,
      signals,
      processingTimeMs: performance.now() - startTime,
      skipped: true,
      skipReason: 'BEC detection error',
    };
  }
}

/**
 * Calculate final weighted score from all layers
 */
function calculateFinalScore(
  results: LayerResult[],
  config: DetectionConfig
): { overallScore: number; confidence: number } {
  // Layer weights (sum to 1.0)
  const weights: Record<string, number> = {
    deterministic: 0.30,
    reputation: 0.15,
    ml: 0.15,
    bec: 0.20,
    llm: 0.12,
    sandbox: 0.08,
  };

  let weightedScore = 0;
  let totalWeight = 0;
  let weightedConfidence = 0;

  for (const result of results) {
    if (result.skipped) continue;

    const layerName = result.layer as string;
    const weight = weights[layerName] || 0.1;
    weightedScore += result.score * weight;
    weightedConfidence += result.confidence * weight;
    totalWeight += weight;
  }

  // Normalize if some layers were skipped
  const normalizedScore = totalWeight > 0 ? weightedScore / totalWeight : 0;
  const normalizedConfidence = totalWeight > 0 ? weightedConfidence / totalWeight : 0;

  // Boost score if multiple critical signals - more aggressive boosting
  const criticalSignals = results.flatMap((r) => r.signals.filter((s) => s.severity === 'critical'));
  const warningSignals = results.flatMap((r) => r.signals.filter((s) => s.severity === 'warning'));

  // Critical signals add 10 points each (max 40), warnings add 3 each (max 15)
  const criticalBoost = Math.min(40, criticalSignals.length * 10);
  const warningBoost = Math.min(15, warningSignals.length * 3);

  return {
    overallScore: Math.min(100, Math.round(normalizedScore * (totalWeight / 0.8) + criticalBoost + warningBoost)),
    confidence: normalizedConfidence,
  };
}

/**
 * Determine verdict based on score thresholds
 */
function determineVerdict(
  score: number,
  config: DetectionConfig
): EmailVerdict['verdict'] {
  if (score >= config.blockThreshold) return 'block';
  if (score >= config.quarantineThreshold) return 'quarantine';
  if (score >= config.suspiciousThreshold) return 'suspicious';
  return 'pass';
}

/**
 * Generate human-readable explanation
 */
function generateExplanation(
  signals: Signal[],
  verdict: EmailVerdict['verdict']
): { explanation: string; recommendation: string } {
  const criticalSignals = signals.filter((s) => s.severity === 'critical');
  const warningSignals = signals.filter((s) => s.severity === 'warning');

  let explanation: string;
  let recommendation: string;

  if (verdict === 'block' || verdict === 'quarantine') {
    const topIssues = criticalSignals.slice(0, 3).map((s) => s.detail);
    explanation = `This email has been flagged due to: ${topIssues.join('; ')}`;

    if (verdict === 'block') {
      recommendation = 'This email has been blocked and will not be delivered. If you believe this is an error, contact your administrator.';
    } else {
      recommendation = 'This email has been quarantined for review. An administrator can release it if deemed safe.';
    }
  } else if (verdict === 'suspicious') {
    const issues = [...criticalSignals, ...warningSignals].slice(0, 2).map((s) => s.detail);
    explanation = `This email shows some suspicious characteristics: ${issues.join('; ')}`;
    recommendation = 'Exercise caution with this email. Do not click links or download attachments unless you verify the sender.';
  } else {
    explanation = 'This email passed security checks.';
    recommendation = 'This email appears to be safe, but always exercise caution with unexpected requests.';
  }

  return { explanation, recommendation };
}

/**
 * Estimate tokens used for billing tracking
 */
function estimateTokensUsed(email: ParsedEmail): number {
  const textLength = (email.body.text?.length || 0) + (email.body.html?.length || 0);
  // Rough approximation: 1 token ≈ 4 characters
  const inputTokens = Math.ceil(textLength / 4) + 500; // +500 for prompt
  const outputTokens = 300; // Typical response size
  return inputTokens + outputTokens;
}

/**
 * Quick check for obviously safe/malicious emails
 * Returns early verdict if high confidence, null if needs full analysis
 */
export async function quickCheck(email: ParsedEmail): Promise<EmailVerdict['verdict'] | null> {
  // Run just deterministic analysis
  const result = await runDeterministicAnalysis(email);

  // If score is very low, it's likely safe
  if (result.score < 15 && result.confidence > 0.8) {
    return 'pass';
  }

  // If score is very high with critical signals, block immediately
  if (result.score >= 80) {
    const hasCritical = result.signals.some((s) => s.severity === 'critical');
    if (hasCritical) {
      return 'block';
    }
  }

  // Needs full analysis
  return null;
}

/**
 * Extract URLs from text content
 */
function extractURLs(text: string): string[] {
  const urlPattern = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  const matches = text.match(urlPattern) || [];

  // Clean up URLs (remove trailing punctuation)
  return matches.map(url => {
    return url.replace(/[.,;:!?)]+$/, '');
  });
}
