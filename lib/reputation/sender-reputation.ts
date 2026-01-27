import { sql } from '../db';
import { getTrustModifier } from './seed-data';

export interface SenderReputation {
  id: string;
  domain: string;
  display_name: string;
  category: 'trusted' | 'marketing' | 'transactional' | 'suspicious' | 'unknown';
  trust_score: number;
  known_tracking_domains: string[];
  email_types: string[];
  first_seen: Date;
  last_seen: Date;
  email_count: number;
  user_feedback: {
    safe: number;
    threat: number;
    spam: number;
  };
  created_at: Date;
  updated_at: Date;
}

export interface EmailFeedback {
  email_id: string;
  user_id: string;
  sender_domain: string;
  original_verdict: string;
  original_score: number;
  corrected_verdict: 'safe' | 'threat' | 'spam';
  reason?: string;
}

/**
 * Get sender reputation by domain
 * Returns null if sender is not in reputation database
 */
export async function getSenderReputation(domain: string): Promise<SenderReputation | null> {
  try {
    const result = await sql`
      SELECT
        id,
        domain,
        display_name,
        category,
        trust_score,
        known_tracking_domains,
        email_types,
        first_seen,
        last_seen,
        email_count,
        user_feedback,
        created_at,
        updated_at
      FROM sender_reputation
      WHERE domain = ${domain}
      LIMIT 1
    `;

    if (result.length === 0) {
      return null;
    }

    return result[0] as SenderReputation;
  } catch (error) {
    console.error('Failed to fetch sender reputation:', error);
    return null;
  }
}

/**
 * Extract domain from email address
 */
export function extractDomain(email: string): string {
  const atIndex = email.lastIndexOf('@');
  if (atIndex === -1) {
    return email.toLowerCase();
  }
  return email.substring(atIndex + 1).toLowerCase();
}

/**
 * Check if URL is from a known tracking domain for this sender
 */
export function isKnownTrackingURL(url: string, reputation: SenderReputation): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    // Check exact match
    if (reputation.known_tracking_domains.includes(hostname)) {
      return true;
    }

    // Check subdomain match (e.g., links.quora.com matches quora.com)
    return reputation.known_tracking_domains.some(domain => {
      return hostname === domain || hostname.endsWith('.' + domain);
    });
  } catch {
    return false;
  }
}

/**
 * Update sender reputation stats after processing email
 */
export async function updateSenderStats(domain: string): Promise<void> {
  try {
    await sql`
      INSERT INTO sender_reputation (
        domain,
        category,
        trust_score,
        email_count,
        last_seen
      ) VALUES (
        ${domain},
        'unknown',
        50,
        1,
        NOW()
      )
      ON CONFLICT (domain)
      DO UPDATE SET
        email_count = sender_reputation.email_count + 1,
        last_seen = NOW()
    `;
  } catch (error) {
    console.error('Failed to update sender stats:', error);
  }
}

/**
 * Record user feedback for an email
 */
export async function recordEmailFeedback(feedback: EmailFeedback): Promise<void> {
  try {
    // Insert feedback record
    await sql`
      INSERT INTO email_feedback (
        email_id,
        user_id,
        sender_domain,
        original_verdict,
        original_score,
        corrected_verdict,
        reason
      ) VALUES (
        ${feedback.email_id},
        ${feedback.user_id},
        ${feedback.sender_domain},
        ${feedback.original_verdict},
        ${feedback.original_score},
        ${feedback.corrected_verdict},
        ${feedback.reason || null}
      )
    `;

    // Update sender reputation feedback stats
    await sql`
      UPDATE sender_reputation
      SET user_feedback = jsonb_set(
        user_feedback,
        ${`{${feedback.corrected_verdict}}`},
        to_jsonb((user_feedback->>${feedback.corrected_verdict})::int + 1)
      )
      WHERE domain = ${feedback.sender_domain}
    `;

  } catch (error) {
    console.error('Failed to record email feedback:', error);
    throw error;
  }
}

/**
 * Calculate adjusted trust score from user feedback
 * If a sender consistently gets "safe" feedback, increase trust
 */
export async function calculateFeedbackTrustScore(domain: string): Promise<number | null> {
  try {
    const [result] = await sql`
      SELECT user_feedback
      FROM sender_reputation
      WHERE domain = ${domain}
      LIMIT 1
    `;

    if (!result) {
      return null;
    }

    const feedback = result.user_feedback as { safe: number; threat: number; spam: number };
    const total = feedback.safe + feedback.threat + feedback.spam;

    if (total < 10) {
      // Not enough feedback to adjust trust
      return null;
    }

    // Calculate trust percentage from feedback
    const safePercentage = (feedback.safe / total) * 100;

    // Map to trust score (80-100 range for high safe percentage)
    if (safePercentage >= 95) return 95;
    if (safePercentage >= 90) return 90;
    if (safePercentage >= 85) return 85;
    if (safePercentage >= 80) return 80;
    if (safePercentage >= 75) return 75;
    if (safePercentage >= 70) return 70;

    // Low trust if many threat/spam reports
    if (safePercentage < 50) return 30;

    return 50; // Neutral
  } catch (error) {
    console.error('Failed to calculate feedback trust score:', error);
    return null;
  }
}

/**
 * Promote sender to trusted list if feedback is consistently positive
 */
export async function promoteToTrustedIfQualified(domain: string): Promise<boolean> {
  try {
    const feedbackTrustScore = await calculateFeedbackTrustScore(domain);

    if (!feedbackTrustScore || feedbackTrustScore < 80) {
      return false; // Not enough positive feedback
    }

    const [sender] = await sql`
      SELECT user_feedback, category
      FROM sender_reputation
      WHERE domain = ${domain}
      LIMIT 1
    `;

    const feedback = sender.user_feedback as { safe: number; threat: number; spam: number };
    const total = feedback.safe + feedback.threat + feedback.spam;

    // Require at least 10 confirmations
    if (feedback.safe < 10) {
      return false;
    }

    // Already in a trusted category
    if (sender.category === 'trusted' || sender.category === 'marketing' || sender.category === 'transactional') {
      return false;
    }

    // Promote to marketing category with calculated trust score
    await sql`
      UPDATE sender_reputation
      SET
        category = 'marketing',
        trust_score = ${feedbackTrustScore}
      WHERE domain = ${domain}
    `;

    console.log(`📈 Promoted ${domain} to trusted (score: ${feedbackTrustScore}, safe feedback: ${feedback.safe}/${total})`);
    return true;

  } catch (error) {
    console.error('Failed to promote sender:', error);
    return false;
  }
}

/**
 * Get list of all trusted senders for a specific category
 */
export async function getTrustedSendersByCategory(category: SenderReputation['category']): Promise<SenderReputation[]> {
  try {
    const result = await sql`
      SELECT *
      FROM sender_reputation
      WHERE category = ${category}
      ORDER BY trust_score DESC, domain ASC
    `;

    return result as SenderReputation[];
  } catch (error) {
    console.error('Failed to fetch trusted senders by category:', error);
    return [];
  }
}

/**
 * Get reputation statistics
 */
export async function getReputationStats(): Promise<{
  total: number;
  by_category: Record<string, number>;
  avg_trust_score: number;
}> {
  try {
    const [statsResult] = await sql`
      SELECT
        COUNT(*) as total,
        ROUND(AVG(trust_score)::numeric, 1) as avg_trust_score
      FROM sender_reputation
    `;

    const categoryResult = await sql`
      SELECT category, COUNT(*) as count
      FROM sender_reputation
      GROUP BY category
    `;

    const by_category: Record<string, number> = {};
    categoryResult.forEach((row: any) => {
      by_category[row.category] = parseInt(row.count);
    });

    return {
      total: parseInt(statsResult.total),
      by_category,
      avg_trust_score: parseFloat(statsResult.avg_trust_score),
    };
  } catch (error) {
    console.error('Failed to fetch reputation stats:', error);
    return {
      total: 0,
      by_category: {},
      avg_trust_score: 0,
    };
  }
}

export { getTrustModifier };
