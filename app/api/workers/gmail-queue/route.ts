/**
 * Gmail Queue Worker
 * Dequeues Gmail ingestion jobs from Upstash and processes them.
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { parseGmailEmail } from '@/lib/detection/parser';
import { storeVerdict } from '@/lib/detection/storage';
import { sendThreatNotification } from '@/lib/notifications/service';
import { getGmailAccessToken, getGmailHistory, getGmailMessage } from '@/lib/integrations/gmail';
import { autoRemediate } from '@/lib/workers/remediation';
import { logAuditEvent } from '@/lib/db/audit';
import {
  dequeueGmailJobs,
  isGmailQueueConfigured,
  moveToDeadLetter,
  requeueGmailJob,
  type GmailQueueJob,
} from '@/lib/queue/gmail';

export const maxDuration = 60;
export const dynamic = 'force-dynamic';

const DEFAULT_BATCH_LIMIT = 10;
const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_TIME_BUDGET_MS = 45_000;
const DEFAULT_MAX_MESSAGES_PER_JOB = 20;

function isRetryableError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message.includes('Too many connections attempts') ||
    message.includes('Failed to acquire permit') ||
    message.includes('fetch') ||
    message.includes('ECONNRESET') ||
    message.includes('ETIMEDOUT')
  );
}

async function processJob(job: GmailQueueJob, timeBudgetMs: number): Promise<{
  processed: number;
  threats: number;
  complete: boolean;
  errors: string[];
}> {
  const errors: string[] = [];
  let processed = 0;
  let threats = 0;
  let complete = true;
  const startTime = Date.now();

  const [integration] = await sql`
    SELECT id, tenant_id, config, nango_connection_id, status
    FROM integrations
    WHERE id = ${job.integrationId}
  `;

  if (!integration || integration.status !== 'connected') {
    return {
      processed,
      threats,
      complete: false,
      errors: ['Integration not found or not connected'],
    };
  }

  if (!integration.nango_connection_id) {
    return {
      processed,
      threats,
      complete: false,
      errors: ['No Nango connection configured'],
    };
  }

  const tenantId = integration.tenant_id as string;
  const config = integration.config as { historyId?: string };

  const accessToken = await getGmailAccessToken(integration.nango_connection_id as string);

  const startHistoryId = config.historyId || job.historyId;
  const historyResult = await getGmailHistory({
    accessToken,
    startHistoryId,
    historyTypes: ['messageAdded'],
  });

  const newMessageIds = new Set<string>();
  for (const entry of historyResult.history) {
    if (entry.messagesAdded) {
      for (const added of entry.messagesAdded) {
        newMessageIds.add(added.message.id);
      }
    }
  }

  const messageLimit = parseInt(
    process.env.GMAIL_QUEUE_MAX_MESSAGES || String(DEFAULT_MAX_MESSAGES_PER_JOB),
    10
  );

  for (const messageId of newMessageIds) {
    if (Date.now() - startTime > timeBudgetMs) {
      complete = false;
      errors.push('Time budget reached');
      break;
    }

    if (processed >= messageLimit) {
      complete = false;
      errors.push('Message limit reached');
      break;
    }

    try {
      const existing = await sql`
        SELECT id FROM email_verdicts
        WHERE tenant_id = ${tenantId}
        AND (message_id LIKE ${`%${messageId}%`} OR message_id = ${messageId})
      `;

      if (existing.length > 0) {
        continue;
      }

      const message = await getGmailMessage({
        accessToken,
        messageId,
        format: 'full',
      });

      const parsedEmail = parseGmailEmail(message);
      const verdict = await analyzeEmail(parsedEmail, tenantId, {
        skipLLM: true,
      });

      await storeVerdict(tenantId, parsedEmail.messageId, verdict, parsedEmail);
      processed++;

      if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
        threats++;

        await sendThreatNotification(tenantId, {
          type: verdict.verdict === 'block' ? 'threat_blocked' : 'threat_quarantined',
          severity: verdict.overallScore >= 80 ? 'critical' : 'warning',
          title: `Email ${verdict.verdict === 'block' ? 'Blocked' : 'Quarantined'}: ${parsedEmail.subject}`,
          message: verdict.explanation || `Threat detected from ${parsedEmail.from.address}`,
          metadata: {
            messageId: parsedEmail.messageId,
            from: parsedEmail.from.address,
            score: verdict.overallScore,
          },
        });

        await autoRemediate({
          tenantId,
          messageId: parsedEmail.messageId,
          externalMessageId: messageId,
          integrationId: integration.id as string,
          integrationType: 'gmail',
          verdict: verdict.verdict,
          score: verdict.overallScore,
        });
      }
    } catch (error) {
      complete = false;
      const errorMsg = error instanceof Error ? error.message : String(error);
      errors.push(errorMsg);
      console.error(`[Gmail Queue] Failed to process message ${messageId}:`, error);
    }
  }

  if (complete) {
    await sql`
      UPDATE integrations
      SET config = config || ${JSON.stringify({ historyId: historyResult.historyId })}::jsonb,
          last_sync_at = NOW(),
          updated_at = NOW()
      WHERE id = ${integration.id}
    `;

    await logAuditEvent({
      tenantId,
      actorId: null,
      actorEmail: 'system',
      action: 'email.sync',
      resourceType: 'integration',
      resourceId: integration.id as string,
      afterState: {
        messagesProcessed: processed,
        historyId: historyResult.historyId,
        integrationType: 'gmail',
      },
    });
  }

  return { processed, threats, complete, errors };
}

export async function GET(request: NextRequest) {
  const authHeader = request.headers.get('authorization');
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  if (!isGmailQueueConfigured()) {
    return NextResponse.json({ status: 'skipped', reason: 'Upstash not configured' });
  }

  const searchParams = request.nextUrl.searchParams;
  const batchLimit = Math.min(
    parseInt(searchParams.get('limit') || String(DEFAULT_BATCH_LIMIT), 10),
    50
  );
  const maxAttempts = parseInt(
    process.env.GMAIL_QUEUE_MAX_ATTEMPTS || String(DEFAULT_MAX_ATTEMPTS),
    10
  );
  const timeBudgetMs = parseInt(
    process.env.GMAIL_QUEUE_TIME_BUDGET_MS || String(DEFAULT_TIME_BUDGET_MS),
    10
  );

  const startTime = Date.now();
  const jobs = await dequeueGmailJobs(batchLimit);

  const summary = {
    success: true,
    fetched: jobs.length,
    processedMessages: 0,
    threatsFound: 0,
    requeued: 0,
    deadLettered: 0,
    errors: [] as string[],
    durationMs: 0,
  };

  for (const job of jobs) {
    if (Date.now() - startTime > timeBudgetMs) {
      await requeueGmailJob(job);
      summary.requeued++;
      continue;
    }

    try {
      const result = await processJob(job, timeBudgetMs - (Date.now() - startTime));
      summary.processedMessages += result.processed;
      summary.threatsFound += result.threats;

      if (!result.complete) {
        const lastError = result.errors[result.errors.length - 1] || 'Incomplete processing';
        const updated = { ...job, attempts: job.attempts + 1, lastError };

        if (!isRetryableError(lastError) || updated.attempts >= maxAttempts) {
          await moveToDeadLetter(updated, lastError);
          summary.deadLettered++;
        } else {
          await requeueGmailJob(updated);
          summary.requeued++;
        }
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      summary.errors.push(errorMsg);

      const updated = { ...job, attempts: job.attempts + 1, lastError: errorMsg };
      if (!isRetryableError(errorMsg) || updated.attempts >= maxAttempts) {
        await moveToDeadLetter(updated, errorMsg);
        summary.deadLettered++;
      } else {
        await requeueGmailJob(updated);
        summary.requeued++;
      }
    }
  }

  summary.durationMs = Date.now() - startTime;
  return NextResponse.json(summary);
}
