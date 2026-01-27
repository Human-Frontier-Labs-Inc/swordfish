/**
 * Enhanced Sender Reputation Lookup
 * Integrates sender_reputation table with threat detection pipeline
 * Phase 1 of False Positive Reduction Strategy
 */

import type { ParsedEmail, LayerResult, Signal } from '../types';
import { checkReputation } from './service';
import {
  getSenderReputation,
  extractDomain,
  isKnownTrackingURL,
  updateSenderStats,
  getTrustModifier,
  type SenderReputation,
} from '@/lib/reputation/sender-reputation';

export interface EnhancedReputationContext {
  senderReputation: SenderReputation | null;
  trustModifier: number;
  knownTrackingDomains: string[];
  isKnownSender: boolean;
  isTrustedCategory: boolean;
}

/**
 * Enhanced reputation lookup that includes sender reputation
 */
export async function runEnhancedReputationLookup(
  email: ParsedEmail
): Promise<{ result: LayerResult; context: EnhancedReputationContext }> {
  const startTime = performance.now();
  const signals: Signal[] = [];

  // Extract sender domain
  const senderEmail = typeof email.from === 'string'
    ? email.from
    : (email.from?.address || '');
  const senderDomain = extractDomain(senderEmail);

  // Get sender reputation from database
  const senderReputation = await getSenderReputation(senderDomain);

  // Calculate trust modifier
  const trustModifier = senderReputation
    ? getTrustModifier(senderReputation.trust_score)
    : 1.0;

  // Determine if trusted
  const isKnownSender = senderReputation !== null;
  const isTrustedCategory = senderReputation
    ? ['trusted', 'marketing', 'transactional'].includes(senderReputation.category)
    : false;

  // Add reputation signal
  if (senderReputation) {
    const scoreReduction = Math.round((1 - trustModifier) * 100);

    signals.push({
      type: 'sender_reputation',
      severity: 'info',
      score: 0, // This doesn't add to score, just provides context
      detail: `Known sender: ${senderReputation.display_name} (${senderReputation.category}, trust: ${senderReputation.trust_score}/100)`,
      metadata: {
        trustScore: senderReputation.trust_score,
        category: senderReputation.category,
        trustModifier,
        scoreReduction: `${scoreReduction}%`,
        emailCount: senderReputation.email_count,
        firstSeen: senderReputation.first_seen,
      },
    });

    // Update stats (fire and forget)
    updateSenderStats(senderDomain).catch(err => {
      console.error('Failed to update sender stats:', err);
    });
  }

  // Run standard reputation checks (domain, IP, URL)
  const domains: string[] = [];
  const ips: string[] = [];
  const urls: string[] = [];
  const emails: string[] = [];

  // Collect sender domain
  if (senderDomain) {
    domains.push(senderDomain);
  }

  // Collect sender email
  if (senderEmail) {
    emails.push(senderEmail);
  }

  // Collect reply-to domain if different
  if (email.replyTo?.address) {
    const replyToDomain = extractDomain(email.replyTo.address);
    if (replyToDomain && replyToDomain !== senderDomain) {
      domains.push(replyToDomain);
      emails.push(email.replyTo.address);
    }
  }

  // Collect URLs from body (extract from text/html)
  const bodyContent = (email.body.text || '') + (email.body.html || '');
  const urlRegex = /https?:\/\/[^\s<>"']+/gi;
  const extractedUrls = bodyContent.match(urlRegex) || [];
  urls.push(...extractedUrls);

  // Run reputation checks
  const reputationResult = await checkReputation({
    domains,
    ips,
    urls,
    emails,
  });

  // Convert reputation results to signals
  // Filter out known tracking URLs if sender is trusted
  for (const urlResult of reputationResult.urls) {
    // Skip if this is a known tracking URL for this sender
    if (senderReputation && isKnownTrackingURL(urlResult.entity, senderReputation)) {
      signals.push({
        type: 'url_reputation',
        severity: 'info',
        score: 0,
        detail: `Known tracking URL for ${senderReputation.display_name} (whitelisted)`,
        metadata: {
          url: urlResult.entity,
          whitelisted: true,
        },
      });
      continue;
    }

    // Standard URL reputation scoring
    if (urlResult.category === 'malicious') {
      signals.push({
        type: 'malicious_url',
        severity: 'critical',
        score: 40,
        detail: `Malicious URL detected: ${urlResult.entity}`,
        metadata: { url: urlResult.entity, category: urlResult.category },
      });
    } else if (urlResult.category === 'suspicious') {
      signals.push({
        type: 'suspicious_url',
        severity: 'warning',
        score: 15, // Reduced from higher values in deterministic layer
        detail: `Suspicious URL: ${urlResult.entity}`,
        metadata: { url: urlResult.entity, category: urlResult.category },
      });
    }
  }

  // Domain reputation signals
  for (const domainResult of reputationResult.domains) {
    if (domainResult.category === 'malicious') {
      signals.push({
        type: 'malicious_domain',
        severity: 'critical',
        score: 35,
        detail: `Malicious domain: ${domainResult.entity}`,
        metadata: { domain: domainResult.entity, category: domainResult.category },
      });
    } else if (domainResult.category === 'suspicious') {
      signals.push({
        type: 'suspicious_domain',
        severity: 'warning',
        score: 20,
        detail: `Suspicious domain: ${domainResult.entity}`,
        metadata: { domain: domainResult.entity, category: domainResult.category },
      });
    }
  }

  // Email reputation signals
  for (const emailResult of reputationResult.emails) {
    if (emailResult.category === 'malicious') {
      signals.push({
        type: 'malicious_sender',
        severity: 'critical',
        score: 40,
        detail: `Malicious sender address: ${emailResult.entity}`,
        metadata: { email: emailResult.entity, category: emailResult.category },
      });
    } else if (emailResult.category === 'suspicious') {
      signals.push({
        type: 'suspicious_sender',
        severity: 'warning',
        score: 25,
        detail: `Suspicious sender address: ${emailResult.entity}`,
        metadata: { email: emailResult.entity, category: emailResult.category },
      });
    }
  }

  // Calculate layer score
  const score = Math.min(100, signals.reduce((sum, s) => sum + s.score, 0));

  const result: LayerResult = {
    layer: 'reputation',
    score,
    confidence: 0.85,
    signals,
    processingTimeMs: performance.now() - startTime,
  };

  const context: EnhancedReputationContext = {
    senderReputation,
    trustModifier,
    knownTrackingDomains: senderReputation?.known_tracking_domains || [],
    isKnownSender,
    isTrustedCategory,
  };

  return { result, context };
}

/**
 * Apply trust modifier to deterministic signals
 * Filters out false positives from known tracking URLs
 */
export function filterDeterministicSignalsWithReputation(
  signals: Signal[],
  context: EnhancedReputationContext
): Signal[] {
  if (!context.senderReputation) {
    return signals; // No filtering if sender is unknown
  }

  const filtered: Signal[] = [];

  for (const signal of signals) {
    // Filter tracking URL signals for trusted senders
    if (
      context.isTrustedCategory &&
      signal.type === 'suspicious_url' &&
      signal.metadata?.url
    ) {
      if (isKnownTrackingURL(signal.metadata.url as string, context.senderReputation)) {
        // Replace with info signal explaining why it was filtered
        filtered.push({
          type: 'url_whitelisted',
          severity: 'info',
          score: 0,
          detail: `Tracking URL whitelisted for ${context.senderReputation.display_name}`,
          metadata: {
            originalSignal: signal.type,
            url: signal.metadata.url,
          },
        });
        continue;
      }
    }

    // Keep all other signals
    filtered.push(signal);
  }

  return filtered;
}

/**
 * Calculate score with trust modifier applied
 */
export function calculateScoreWithTrust(
  baseScore: number,
  context: EnhancedReputationContext
): { adjustedScore: number; reduction: number; reductionPercent: number } {
  const adjustedScore = Math.round(baseScore * context.trustModifier);
  const reduction = baseScore - adjustedScore;
  const reductionPercent = baseScore > 0 ? (reduction / baseScore) * 100 : 0;

  return {
    adjustedScore,
    reduction,
    reductionPercent,
  };
}
