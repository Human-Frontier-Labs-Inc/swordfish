/**
 * Webhook Processing Queue
 * Provides reliable webhook processing with retries and dead-letter handling
 */

import { sql } from '@/lib/db';

export interface WebhookJob {
  id: string;
  type: 'gmail' | 'microsoft' | 'smtp';
  payload: Record<string, unknown>;
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'dead';
  attempts: number;
  maxAttempts: number;
  lastError: string | null;
  nextRetryAt: Date | null;
  createdAt: Date;
  completedAt: Date | null;
  tenantId: string | null;
  integrationId: string | null;
  processingTimeMs: number | null;
}

// Database row type (snake_case column names)
interface WebhookJobRow {
  id: string;
  type: string;
  payload: Record<string, unknown>;
  status: string;
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  next_retry_at: string | null;
  created_at: string;
  completed_at: string | null;
  tenant_id: string | null;
  integration_id: string | null;
  processing_time_ms: number | null;
}

// In-memory queue for fast processing (backed by database for persistence)
const memoryQueue: WebhookJob[] = [];
let isProcessing = false;

// Retry delays with exponential backoff (in ms)
const RETRY_DELAYS = [
  1000,      // 1 second
  5000,      // 5 seconds
  30000,     // 30 seconds
  60000,     // 1 minute
  300000,    // 5 minutes
];

/**
 * Enqueue a webhook for processing
 */
export async function enqueueWebhook(params: {
  type: 'gmail' | 'microsoft' | 'smtp';
  payload: Record<string, unknown>;
  tenantId?: string;
  integrationId?: string;
  immediate?: boolean;
}): Promise<string> {
  const { type, payload, tenantId, integrationId, immediate = false } = params;

  const id = crypto.randomUUID();

  const job: WebhookJob = {
    id,
    type,
    payload,
    status: 'pending',
    attempts: 0,
    maxAttempts: RETRY_DELAYS.length + 1,
    lastError: null,
    nextRetryAt: null,
    createdAt: new Date(),
    completedAt: null,
    tenantId: tenantId || null,
    integrationId: integrationId || null,
    processingTimeMs: null,
  };

  // Store in database for persistence
  await sql`
    INSERT INTO webhook_jobs (
      id, type, payload, status, attempts, max_attempts,
      tenant_id, integration_id, created_at
    ) VALUES (
      ${id}, ${type}, ${JSON.stringify(payload)}::jsonb, 'pending', 0, ${job.maxAttempts},
      ${tenantId || null}, ${integrationId || null}, NOW()
    )
    ON CONFLICT (id) DO NOTHING
  `.catch(() => {
    // Table might not exist, use memory queue only
    console.log('webhook_jobs table not found, using memory queue');
  });

  // Add to memory queue
  memoryQueue.push(job);

  // Process immediately if requested
  if (immediate) {
    processQueue().catch(console.error);
  }

  return id;
}

/**
 * Process queued webhooks
 */
export async function processQueue(): Promise<void> {
  if (isProcessing) return;
  isProcessing = true;

  try {
    while (memoryQueue.length > 0) {
      const job = memoryQueue.shift();
      if (!job) break;

      // Skip if not ready for retry
      if (job.nextRetryAt && job.nextRetryAt > new Date()) {
        memoryQueue.push(job); // Re-queue for later
        continue;
      }

      await processJob(job);
    }

    // Also check database for any pending jobs
    const pendingJobs = await sql`
      SELECT * FROM webhook_jobs
      WHERE status = 'pending'
      AND (next_retry_at IS NULL OR next_retry_at <= NOW())
      ORDER BY created_at ASC
      LIMIT 10
    `.catch(() => [] as WebhookJobRow[]) as WebhookJobRow[];

    for (const dbJob of pendingJobs) {
      const job: WebhookJob = {
        id: dbJob.id,
        type: dbJob.type as 'gmail' | 'microsoft' | 'smtp',
        payload: dbJob.payload,
        status: dbJob.status as WebhookJob['status'],
        attempts: dbJob.attempts,
        maxAttempts: dbJob.max_attempts,
        lastError: dbJob.last_error,
        nextRetryAt: dbJob.next_retry_at ? new Date(dbJob.next_retry_at) : null,
        createdAt: new Date(dbJob.created_at),
        completedAt: dbJob.completed_at ? new Date(dbJob.completed_at) : null,
        tenantId: dbJob.tenant_id,
        integrationId: dbJob.integration_id,
        processingTimeMs: dbJob.processing_time_ms,
      };

      await processJob(job);
    }
  } finally {
    isProcessing = false;
  }
}

/**
 * Process a single webhook job
 */
async function processJob(job: WebhookJob): Promise<void> {
  const startTime = Date.now();
  job.status = 'processing';
  job.attempts++;

  try {
    // Import handlers dynamically to avoid circular dependencies
    const { processGmailWebhook } = await import('./handlers/gmail');
    const { processMicrosoftWebhook } = await import('./handlers/microsoft');

    switch (job.type) {
      case 'gmail':
        await processGmailWebhook(job.payload);
        break;
      case 'microsoft':
        await processMicrosoftWebhook(job.payload);
        break;
      case 'smtp':
        // SMTP webhooks are processed synchronously
        break;
      default:
        throw new Error(`Unknown webhook type: ${job.type}`);
    }

    // Success
    job.status = 'completed';
    job.completedAt = new Date();
    job.processingTimeMs = Date.now() - startTime;

    await updateJobStatus(job);
  } catch (error) {
    job.lastError = error instanceof Error ? error.message : 'Unknown error';
    job.processingTimeMs = Date.now() - startTime;

    if (job.attempts >= job.maxAttempts) {
      // Move to dead letter queue
      job.status = 'dead';
      console.error(`Webhook job ${job.id} moved to dead letter queue:`, job.lastError);
    } else {
      // Schedule retry
      job.status = 'pending';
      const delayIndex = Math.min(job.attempts - 1, RETRY_DELAYS.length - 1);
      job.nextRetryAt = new Date(Date.now() + RETRY_DELAYS[delayIndex]);
      memoryQueue.push(job);
    }

    await updateJobStatus(job);
  }
}

/**
 * Update job status in database
 */
async function updateJobStatus(job: WebhookJob): Promise<void> {
  await sql`
    UPDATE webhook_jobs
    SET
      status = ${job.status},
      attempts = ${job.attempts},
      last_error = ${job.lastError},
      next_retry_at = ${job.nextRetryAt?.toISOString() || null},
      completed_at = ${job.completedAt?.toISOString() || null},
      processing_time_ms = ${job.processingTimeMs}
    WHERE id = ${job.id}
  `.catch(() => {
    // Table might not exist
  });
}

/**
 * Get queue statistics
 */
export async function getQueueStats(): Promise<{
  pending: number;
  processing: number;
  completed: number;
  failed: number;
  dead: number;
  avgProcessingTimeMs: number;
}> {
  const stats = await sql`
    SELECT
      status,
      COUNT(*) as count,
      AVG(processing_time_ms) as avg_time
    FROM webhook_jobs
    WHERE created_at > NOW() - INTERVAL '24 hours'
    GROUP BY status
  `.catch(() => []);

  const result = {
    pending: 0,
    processing: 0,
    completed: 0,
    failed: 0,
    dead: 0,
    avgProcessingTimeMs: 0,
  };

  let totalTime = 0;
  let totalCompleted = 0;

  for (const row of stats) {
    const status = row.status as keyof typeof result;
    const count = parseInt(row.count as string, 10);

    if (status in result && status !== 'avgProcessingTimeMs') {
      (result[status] as number) = count;
    }

    if (status === 'completed') {
      totalTime = parseFloat(row.avg_time as string) || 0;
      totalCompleted = count;
    }
  }

  result.avgProcessingTimeMs = totalCompleted > 0 ? totalTime : 0;

  // Add in-memory queue stats
  result.pending += memoryQueue.filter(j => j.status === 'pending').length;
  result.processing += memoryQueue.filter(j => j.status === 'processing').length;

  return result;
}

/**
 * Retry a specific failed job
 */
export async function retryJob(jobId: string): Promise<boolean> {
  const jobs = await sql`
    SELECT * FROM webhook_jobs WHERE id = ${jobId}
  `.catch(() => [] as WebhookJobRow[]) as WebhookJobRow[];

  if (jobs.length === 0) return false;

  const dbJob = jobs[0];

  const job: WebhookJob = {
    id: dbJob.id,
    type: dbJob.type as 'gmail' | 'microsoft' | 'smtp',
    payload: dbJob.payload,
    status: 'pending',
    attempts: dbJob.attempts,
    maxAttempts: dbJob.max_attempts + 1, // Give one more attempt
    lastError: null,
    nextRetryAt: null,
    createdAt: new Date(dbJob.created_at),
    completedAt: null,
    tenantId: dbJob.tenant_id,
    integrationId: dbJob.integration_id,
    processingTimeMs: null,
  };

  memoryQueue.push(job);

  await sql`
    UPDATE webhook_jobs
    SET status = 'pending', next_retry_at = NULL, max_attempts = max_attempts + 1
    WHERE id = ${jobId}
  `.catch(() => {});

  processQueue().catch(console.error);

  return true;
}

/**
 * Get dead letter jobs for review
 */
export async function getDeadLetterJobs(limit = 50): Promise<WebhookJob[]> {
  const jobs = await sql`
    SELECT * FROM webhook_jobs
    WHERE status = 'dead'
    ORDER BY created_at DESC
    LIMIT ${limit}
  `.catch(() => [] as WebhookJobRow[]) as WebhookJobRow[];

  return jobs.map(row => ({
    id: row.id,
    type: row.type as 'gmail' | 'microsoft' | 'smtp',
    payload: row.payload,
    status: 'dead' as const,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    lastError: row.last_error,
    nextRetryAt: null,
    createdAt: new Date(row.created_at),
    completedAt: null,
    tenantId: row.tenant_id,
    integrationId: row.integration_id,
    processingTimeMs: row.processing_time_ms,
  }));
}
