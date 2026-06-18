/**
 * Detection Results Storage
 * Persists email verdicts and related data to the database
 */

import { sql } from '@/lib/db';
import type { EmailVerdict, Signal, ParsedEmail } from './types';
import { loggers } from '@/lib/logging/logger';

// Helper to truncate strings to fit database column limits
function truncate(str: string | null | undefined, maxLength: number): string | null {
  if (!str) return null;
  return str.length > maxLength ? str.substring(0, maxLength - 3) + '...' : str;
}

/**
 * Store an email verdict in the database
 */
export async function storeVerdict(
  tenantId: string,
  messageId: string,
  verdict: EmailVerdict,
  email?: ParsedEmail
): Promise<string> {
  // Do not persist verdicts from failed analysis runs.
  // This prevents emails from being falsely marked as "analyzed" when the
  // detection pipeline encountered a fatal error.
  if (verdict.analysisStatus === 'analysis_failed') {
    loggers.db.warn('Skipping verdict storage for failed analysis', {
      tenantId,
      messageId,
      analysisError: verdict.analysisError,
    });
    return '';
  }

  // Truncate all string fields to fit database limits (use 250 to be safe with VARCHAR(255))
  const safeMessageId = truncate(messageId, 250);
  const safeSubject = truncate(email?.subject, 250);
  const safeFromAddress = truncate(email?.from?.address, 250);
  const safeFromDisplayName = truncate(email?.from?.displayName, 250);
  const safeExplanation = truncate(verdict.explanation, 1000);
  const safeRecommendation = truncate(verdict.recommendation, 1000);

  const result = await sql`
    INSERT INTO email_verdicts (
      tenant_id,
      message_id,
      subject,
      from_address,
      from_display_name,
      to_addresses,
      received_at,
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
      ${safeMessageId},
      ${safeSubject},
      ${safeFromAddress},
      ${safeFromDisplayName},
      ${email?.to ? JSON.stringify(email.to) : null},
      ${email?.date || null},
      ${verdict.verdict},
      ${verdict.overallScore},
      ${verdict.confidence},
      ${JSON.stringify(verdict.signals)},
      ${JSON.stringify(verdict.layerResults || {})},
      ${safeExplanation},
      ${safeRecommendation},
      ${Math.round(verdict.processingTimeMs || 0)},
      ${verdict.llmTokensUsed || null}
    )
    ON CONFLICT (tenant_id, message_id) DO UPDATE SET
      subject = COALESCE(EXCLUDED.subject, email_verdicts.subject),
      from_address = COALESCE(EXCLUDED.from_address, email_verdicts.from_address),
      from_display_name = COALESCE(EXCLUDED.from_display_name, email_verdicts.from_display_name),
      to_addresses = COALESCE(EXCLUDED.to_addresses, email_verdicts.to_addresses),
      received_at = COALESCE(EXCLUDED.received_at, email_verdicts.received_at),
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
      ${truncate(email.messageId, 250)},
      ${truncate(email.subject, 250)},
      ${truncate(email.from.address, 250)},
      ${truncate(email.to[0]?.address, 250) || ''},
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
      subject,
      from_address,
      from_display_name,
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
    subject: (r.subject as string) || 'No Subject',
    sender: (r.from_display_name as string) || (r.from_address as string) || 'Unknown Sender',
    verdict: r.verdict as string,
    score: r.score as number,
    signals: r.signals as Signal[],
    createdAt: r.created_at as Date,
  }));
}

/**
 * Threat record as consumed by the threat-management UI.
 *
 * The live detection pipeline persists every analyzed email to `email_verdicts`
 * (keyed by the Clerk tenant string + message_id). The legacy `threats` table is
 * NOT populated by the live path, so the threat-management screens read from
 * `email_verdicts` here to stay consistent with the dashboard and Emails pages.
 *
 * `id` is the URL-safe-encoded message_id so the detail route can round-trip it.
 */
export interface ManagedThreat {
  id: string;
  message_id: string;
  subject: string;
  sender_email: string;
  sender_name: string;
  recipient_email: string;
  threat_type: string;
  verdict: string;
  score: number;
  status: string;
  quarantined_at: Date | null;
  explanation: string;
  signals: Signal[];
}

/**
 * Map an email_verdicts verdict value to a UI "status".
 * email_verdicts has no quarantine lifecycle of its own, so we derive a sensible
 * status from the verdict + any recorded action_taken / user_feedback.
 */
function deriveThreatStatus(row: Record<string, unknown>): string {
  const action = (row.action_taken as string | null) || null;
  if (action === 'released' || action === 'delivered') return 'released';
  if (action === 'deleted') return 'deleted';
  if ((row.user_feedback as string | null) === 'false_positive') return 'released';
  const verdict = row.verdict as string;
  if (verdict === 'quarantine' || verdict === 'block') return 'quarantined';
  return 'quarantined';
}

/**
 * Derive a coarse threat_type from the verdict signals so the UI can show a badge.
 */
function deriveThreatType(signals: Signal[] | null | undefined): string {
  const types = new Set<string>((signals || []).map((s) => String(s.type)));
  if (types.has('credential_request')) return 'phishing';
  if (types.has('financial_request') || types.has('bec_detected') || types.has('bec_impersonation')) {
    return 'bec';
  }
  if (types.has('executable') || types.has('macro_enabled') || types.has('dangerous_attachment')) {
    return 'malware';
  }
  if (
    types.has('homoglyph') ||
    types.has('display_name_spoof') ||
    types.has('dangerous_url') ||
    types.has('ip_url')
  ) {
    return 'phishing';
  }
  if (types.has('spam') || types.has('bulk_sender')) return 'spam';
  return 'phishing';
}

function mapVerdictRowToThreat(row: Record<string, unknown>): ManagedThreat {
  const signals = (row.signals as Signal[]) || [];
  const messageId = row.message_id as string;
  return {
    id: encodeURIComponent(messageId),
    message_id: messageId,
    subject: (row.subject as string) || '(No subject)',
    sender_email: (row.from_address as string) || 'unknown',
    sender_name: (row.from_display_name as string) || '',
    recipient_email: '',
    threat_type: deriveThreatType(signals),
    verdict: row.verdict as string,
    score: (row.score as number) || 0,
    status: deriveThreatStatus(row),
    quarantined_at: row.created_at ? new Date(row.created_at as string) : null,
    explanation: (row.explanation as string) || (row.llm_explanation as string) || '',
    signals,
  };
}

/**
 * Get threats for the threat-management UI, sourced from email_verdicts.
 *
 * Only threatening verdicts (suspicious/quarantine/block) are returned so the
 * page mirrors what the dashboard "top threats" widget shows.
 */
export async function getThreatsForManagement(
  tenantId: string,
  options: {
    status?: 'all' | 'quarantined' | 'released' | 'deleted';
    limit?: number;
    offset?: number;
  } = {}
): Promise<ManagedThreat[]> {
  const { limit = 50, offset = 0 } = options;

  const results = (await sql`
    SELECT
      message_id,
      subject,
      from_address,
      from_display_name,
      signals,
      verdict,
      score,
      explanation,
      llm_explanation,
      action_taken,
      user_feedback,
      created_at
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND verdict IN ('suspicious', 'quarantine', 'block')
    ORDER BY created_at DESC
    LIMIT ${limit} OFFSET ${offset}
  `) as Array<Record<string, unknown>>;

  const threats = results.map(mapVerdictRowToThreat);

  // Status filtering is applied in-memory because the status is derived.
  const status = options.status || 'all';
  if (status === 'all') return threats;
  return threats.filter((t) => t.status === status);
}

/**
 * Get a single managed threat by its (encoded or raw) message id.
 */
export async function getThreatByMessageId(
  tenantId: string,
  rawId: string
): Promise<(ManagedThreat & { recommendation: string }) | null> {
  // The id may arrive URL-encoded (message ids contain <, >, @).
  let messageId = rawId;
  try {
    messageId = decodeURIComponent(rawId);
  } catch {
    // rawId was not valid percent-encoding; use as-is.
    messageId = rawId;
  }

  const results = (await sql`
    SELECT
      message_id,
      subject,
      from_address,
      from_display_name,
      signals,
      verdict,
      score,
      explanation,
      llm_explanation,
      llm_recommendation,
      action_taken,
      user_feedback,
      created_at
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND message_id = ${messageId}
    LIMIT 1
  `) as Array<Record<string, unknown>>;

  if (results.length === 0) return null;

  const row = results[0];
  return {
    ...mapVerdictRowToThreat(row),
    recommendation: (row.llm_recommendation as string) || '',
  };
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
