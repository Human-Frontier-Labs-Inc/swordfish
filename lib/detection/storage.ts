/**
 * Detection Results Storage
 * Persists email verdicts and related data to the database
 */

import { sql } from '@/lib/db';
import type { EmailVerdict, Signal } from './types';

/**
 * Store an email verdict in the database
 */
export async function storeVerdict(
  tenantId: string,
  messageId: string,
  verdict: EmailVerdict
): Promise<string> {
  const result = await sql`
    INSERT INTO email_verdicts (
      tenant_id,
      message_id,
      verdict,
      score,
      confidence,
      signals,
      layer_results,
      explanation,
      recommendation,
      processing_time_ms,
      llm_tokens_used
    ) VALUES (
      ${tenantId},
      ${messageId},
      ${verdict.verdict},
      ${verdict.overallScore},
      ${verdict.confidence},
      ${JSON.stringify(verdict.signals)},
      ${JSON.stringify(verdict.layerResults || {})},
      ${verdict.explanation || null},
      ${verdict.recommendation || null},
      ${verdict.processingTimeMs || 0},
      ${verdict.llmTokensUsed || null}
    )
    ON CONFLICT (tenant_id, message_id) DO UPDATE SET
      verdict = EXCLUDED.verdict,
      score = EXCLUDED.score,
      confidence = EXCLUDED.confidence,
      signals = EXCLUDED.signals,
      updated_at = NOW()
    RETURNING id
  `;

  return result[0].id as string;
}

/**
 * Store a threat record for quarantine management
 */
export async function storeThreat(
  tenantId: string,
  email: {
    messageId: string;
    subject: string;
    from: { address: string; displayName?: string };
    to: Array<{ address: string; displayName?: string }>;
    receivedAt: Date;
  },
  verdict: EmailVerdict
): Promise<string> {
  const signalTypes = verdict.signals
    .filter(s => s.severity === 'critical' || s.severity === 'warning')
    .map(s => s.type);

  const result = await sql`
    INSERT INTO threats (
      tenant_id,
      message_id,
      subject,
      sender_email,
      recipient_email,
      verdict,
      score,
      categories,
      signals,
      status,
      received_at
    ) VALUES (
      ${tenantId},
      ${email.messageId},
      ${email.subject},
      ${email.from.address},
      ${email.to[0]?.address || ''},
      ${verdict.verdict},
      ${verdict.overallScore},
      ${JSON.stringify(signalTypes)},
      ${JSON.stringify(verdict.signals)},
      'quarantined',
      ${email.receivedAt}
    )
    ON CONFLICT (tenant_id, message_id) DO UPDATE SET
      verdict = EXCLUDED.verdict,
      score = EXCLUDED.score,
      updated_at = NOW()
    RETURNING id
  `;

  return result[0].id as string;
}

/**
 * Get a verdict by message ID
 */
export async function getVerdictByMessageId(
  tenantId: string,
  messageId: string
): Promise<Record<string, unknown> | null> {
  const results = await sql`
    SELECT * FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND message_id = ${messageId}
    LIMIT 1
  `;

  return (results[0] as Record<string, unknown>) || null;
}

/**
 * Get recent verdicts for a tenant
 */
export async function getRecentVerdicts(
  tenantId: string,
  limit: number = 50,
  offset: number = 0
): Promise<Record<string, unknown>[]> {
  const results = await sql`
    SELECT * FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    ORDER BY created_at DESC
    LIMIT ${limit}
    OFFSET ${offset}
  `;
  return results as Record<string, unknown>[];
}

/**
 * Get verdict statistics for a tenant
 */
export async function getVerdictStats(
  tenantId: string,
  daysBack: number = 7
): Promise<{
  total: number;
  passed: number;
  suspicious: number;
  quarantined: number;
  blocked: number;
  avgScore: number;
  avgProcessingTime: number;
}> {
  const results = await sql`
    SELECT
      COUNT(*)::int as total,
      COUNT(*) FILTER (WHERE verdict = 'pass')::int as passed,
      COUNT(*) FILTER (WHERE verdict = 'suspicious')::int as suspicious,
      COUNT(*) FILTER (WHERE verdict = 'quarantine')::int as quarantined,
      COUNT(*) FILTER (WHERE verdict = 'block')::int as blocked,
      COALESCE(AVG(score), 0)::float as avg_score,
      COALESCE(AVG(processing_time_ms), 0)::float as avg_processing_time
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
  ` as Array<{
    total: number;
    passed: number;
    suspicious: number;
    quarantined: number;
    blocked: number;
    avg_score: number;
    avg_processing_time: number;
  }>;

  const stats = results[0] || {
    total: 0,
    passed: 0,
    suspicious: 0,
    quarantined: 0,
    blocked: 0,
    avg_score: 0,
    avg_processing_time: 0,
  };

  return {
    total: stats.total || 0,
    passed: stats.passed || 0,
    suspicious: stats.suspicious || 0,
    quarantined: stats.quarantined || 0,
    blocked: stats.blocked || 0,
    avgScore: stats.avg_score || 0,
    avgProcessingTime: stats.avg_processing_time || 0,
  };
}

/**
 * Get top threats for a tenant
 */
export async function getTopThreats(
  tenantId: string,
  limit: number = 10
): Promise<Array<{
  messageId: string;
  subject: string;
  sender: string;
  verdict: string;
  score: number;
  signals: Signal[];
  createdAt: Date;
}>> {
  const results = await sql`
    SELECT
      message_id,
      signals,
      verdict,
      score,
      created_at
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND verdict IN ('suspicious', 'quarantine', 'block')
    ORDER BY score DESC, created_at DESC
    LIMIT ${limit}
  ` as Array<Record<string, unknown>>;

  return results.map((r) => ({
    messageId: r.message_id as string,
    subject: 'Unknown', // Would need to join with emails table
    sender: 'Unknown',
    verdict: r.verdict as string,
    score: r.score as number,
    signals: r.signals as Signal[],
    createdAt: r.created_at as Date,
  }));
}

/**
 * Quarantine an email
 */
export async function quarantineEmail(
  tenantId: string,
  verdictId: string,
  originalLocation: string
): Promise<string> {
  const result = await sql`
    INSERT INTO quarantine (
      tenant_id,
      verdict_id,
      original_location,
      status
    ) VALUES (
      ${tenantId},
      ${verdictId},
      ${originalLocation},
      'quarantined'
    )
    RETURNING id
  `;

  return result[0].id;
}

/**
 * Release email from quarantine
 */
export async function releaseFromQuarantine(
  tenantId: string,
  quarantineId: string,
  releasedBy: string
): Promise<void> {
  await sql`
    UPDATE quarantine
    SET
      status = 'released',
      released_at = NOW(),
      released_by = ${releasedBy}
    WHERE id = ${quarantineId}
    AND tenant_id = ${tenantId}
  `;
}

/**
 * Get quarantined emails for a tenant
 */
export async function getQuarantinedEmails(
  tenantId: string,
  status: 'quarantined' | 'released' | 'deleted' = 'quarantined',
  limit: number = 50
): Promise<Array<{
  id: string;
  verdictId: string;
  originalLocation: string;
  status: string;
  quarantinedAt: Date;
  expiresAt: Date;
}>> {
  const results = await sql`
    SELECT
      id,
      verdict_id,
      original_location,
      status,
      quarantined_at,
      expires_at
    FROM quarantine
    WHERE tenant_id = ${tenantId}
    AND status = ${status}
    ORDER BY quarantined_at DESC
    LIMIT ${limit}
  ` as Array<Record<string, unknown>>;

  return results.map((r) => ({
    id: r.id as string,
    verdictId: r.verdict_id as string,
    originalLocation: r.original_location as string,
    status: r.status as string,
    quarantinedAt: r.quarantined_at as Date,
    expiresAt: r.expires_at as Date,
  }));
}
