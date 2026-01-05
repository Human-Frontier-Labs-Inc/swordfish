/**
 * Outbound Webhook System
 *
 * Delivers webhook events to configured endpoints with retry logic
 */

import { sql } from '@/lib/db';
import { nanoid } from 'nanoid';
import crypto from 'crypto';

export type WebhookEventType =
  | 'threat.detected'
  | 'threat.blocked'
  | 'threat.quarantined'
  | 'threat.released'
  | 'threat.deleted'
  | 'policy.created'
  | 'policy.updated'
  | 'policy.deleted'
  | 'quarantine.released'
  | 'quarantine.expired'
  | 'integration.connected'
  | 'integration.disconnected'
  | 'integration.error';

export interface WebhookConfig {
  id: string;
  tenantId: string;
  name: string;
  url: string;
  secret: string;
  events: WebhookEventType[];
  isActive: boolean;
  headers?: Record<string, string>;
  retryCount: number;
  retryDelayMs: number;
  timeoutMs: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface WebhookPayload {
  id: string;
  event: WebhookEventType;
  timestamp: string;
  tenantId: string;
  data: Record<string, unknown>;
  metadata?: {
    version: string;
    source: string;
  };
}

export interface WebhookDeliveryResult {
  success: boolean;
  webhookId: string;
  eventId: string;
  statusCode?: number;
  responseBody?: string;
  error?: string;
  attempts: number;
  duration: number;
}

interface DeliveryAttempt {
  attempt: number;
  statusCode?: number;
  error?: string;
  timestamp: string;
  duration: number;
}

/**
 * Generate HMAC signature for webhook payload
 */
export function generateSignature(payload: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

/**
 * Verify webhook signature
 */
export function verifySignature(
  payload: string,
  signature: string,
  secret: string
): boolean {
  const expected = generateSignature(payload, secret);
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

/**
 * Create webhook payload
 */
export function createPayload(
  event: WebhookEventType,
  tenantId: string,
  data: Record<string, unknown>
): WebhookPayload {
  return {
    id: nanoid(),
    event,
    timestamp: new Date().toISOString(),
    tenantId,
    data,
    metadata: {
      version: '1.0',
      source: 'swordfish',
    },
  };
}

/**
 * Deliver webhook with retries
 */
export async function deliverWebhook(
  webhook: WebhookConfig,
  payload: WebhookPayload
): Promise<WebhookDeliveryResult> {
  const startTime = Date.now();
  const attempts: DeliveryAttempt[] = [];
  const payloadString = JSON.stringify(payload);
  const signature = generateSignature(payloadString, webhook.secret);

  for (let attempt = 1; attempt <= webhook.retryCount + 1; attempt++) {
    const attemptStart = Date.now();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), webhook.timeoutMs);

      const response = await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Webhook-Id': webhook.id,
          'X-Webhook-Event': payload.event,
          'X-Webhook-Signature': `sha256=${signature}`,
          'X-Webhook-Timestamp': payload.timestamp,
          'X-Webhook-Delivery': payload.id,
          'User-Agent': 'Swordfish-Webhook/1.0',
          ...webhook.headers,
        },
        body: payloadString,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const duration = Date.now() - attemptStart;
      const responseBody = await response.text().catch(() => '');

      attempts.push({
        attempt,
        statusCode: response.status,
        timestamp: new Date().toISOString(),
        duration,
      });

      // Success: 2xx status codes
      if (response.ok) {
        await logDelivery(webhook.id, payload, attempts, true);
        return {
          success: true,
          webhookId: webhook.id,
          eventId: payload.id,
          statusCode: response.status,
          responseBody,
          attempts: attempt,
          duration: Date.now() - startTime,
        };
      }

      // Don't retry on 4xx errors (except 429)
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        await logDelivery(webhook.id, payload, attempts, false);
        return {
          success: false,
          webhookId: webhook.id,
          eventId: payload.id,
          statusCode: response.status,
          responseBody,
          error: `HTTP ${response.status}`,
          attempts: attempt,
          duration: Date.now() - startTime,
        };
      }

      // Wait before retry with exponential backoff
      if (attempt <= webhook.retryCount) {
        const delay = webhook.retryDelayMs * Math.pow(2, attempt - 1);
        await sleep(Math.min(delay, 30000)); // Max 30s delay
      }
    } catch (error) {
      const duration = Date.now() - attemptStart;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      attempts.push({
        attempt,
        error: errorMessage,
        timestamp: new Date().toISOString(),
        duration,
      });

      // Wait before retry
      if (attempt <= webhook.retryCount) {
        const delay = webhook.retryDelayMs * Math.pow(2, attempt - 1);
        await sleep(Math.min(delay, 30000));
      }
    }
  }

  // All attempts failed
  await logDelivery(webhook.id, payload, attempts, false);
  return {
    success: false,
    webhookId: webhook.id,
    eventId: payload.id,
    error: 'All delivery attempts failed',
    attempts: webhook.retryCount + 1,
    duration: Date.now() - startTime,
  };
}

/**
 * Log webhook delivery attempt
 */
async function logDelivery(
  webhookId: string,
  payload: WebhookPayload,
  attempts: DeliveryAttempt[],
  success: boolean
): Promise<void> {
  try {
    await sql`
      INSERT INTO webhook_deliveries (
        id, webhook_id, tenant_id, event_type, event_id, payload,
        attempts, success, created_at
      )
      VALUES (
        ${nanoid()},
        ${webhookId},
        ${payload.tenantId},
        ${payload.event},
        ${payload.id},
        ${JSON.stringify(payload)},
        ${JSON.stringify(attempts)},
        ${success},
        NOW()
      )
    `;
  } catch (error) {
    console.error('Failed to log webhook delivery:', error);
  }
}

/**
 * Get active webhooks for a tenant and event type
 */
export async function getWebhooksForEvent(
  tenantId: string,
  event: WebhookEventType
): Promise<WebhookConfig[]> {
  const result = await sql`
    SELECT * FROM webhooks
    WHERE tenant_id = ${tenantId}
      AND is_active = true
      AND ${event} = ANY(events)
  `;

  return result.map((row: Record<string, unknown>) => ({
    id: row.id as string,
    tenantId: row.tenant_id as string,
    name: row.name as string,
    url: row.url as string,
    secret: row.secret as string,
    events: row.events as WebhookEventType[],
    isActive: row.is_active as boolean,
    headers: row.headers as Record<string, string> | undefined,
    retryCount: (row.retry_count as number) || 3,
    retryDelayMs: (row.retry_delay_ms as number) || 1000,
    timeoutMs: (row.timeout_ms as number) || 30000,
    createdAt: row.created_at as Date,
    updatedAt: row.updated_at as Date,
  }));
}

/**
 * Dispatch event to all matching webhooks
 */
export async function dispatchEvent(
  tenantId: string,
  event: WebhookEventType,
  data: Record<string, unknown>
): Promise<WebhookDeliveryResult[]> {
  const webhooks = await getWebhooksForEvent(tenantId, event);

  if (webhooks.length === 0) {
    return [];
  }

  const payload = createPayload(event, tenantId, data);
  const results = await Promise.all(
    webhooks.map((webhook) => deliverWebhook(webhook, payload))
  );

  return results;
}

/**
 * Test webhook endpoint
 */
export async function testWebhook(
  webhook: WebhookConfig
): Promise<WebhookDeliveryResult> {
  const payload = createPayload('threat.detected', webhook.tenantId, {
    test: true,
    message: 'This is a test webhook delivery',
    timestamp: new Date().toISOString(),
  });

  return deliverWebhook(webhook, payload);
}

/**
 * Get webhook delivery history
 */
export async function getDeliveryHistory(
  webhookId: string,
  limit = 50
): Promise<Record<string, unknown>[]> {
  const result = await sql`
    SELECT * FROM webhook_deliveries
    WHERE webhook_id = ${webhookId}
    ORDER BY created_at DESC
    LIMIT ${limit}
  `;

  return result.map((row: Record<string, unknown>) => ({
    id: row.id,
    eventType: row.event_type,
    eventId: row.event_id,
    payload: row.payload,
    attempts: row.attempts,
    success: row.success,
    createdAt: row.created_at,
  }));
}

/**
 * Calculate webhook health metrics
 */
export async function getWebhookHealth(
  webhookId: string
): Promise<{
  successRate: number;
  avgLatency: number;
  totalDeliveries: number;
  failedDeliveries: number;
  lastDelivery: Date | null;
}> {
  const result = await sql`
    SELECT
      COUNT(*)::int as total,
      COUNT(*) FILTER (WHERE success = true)::int as successful,
      AVG(
        (attempts->-1->>'duration')::int
      ) as avg_latency,
      MAX(created_at) as last_delivery
    FROM webhook_deliveries
    WHERE webhook_id = ${webhookId}
      AND created_at > NOW() - INTERVAL '7 days'
  `;

  const row = result[0] || { total: 0, successful: 0, avg_latency: 0, last_delivery: null };
  const total = row.total || 0;
  const successful = row.successful || 0;

  return {
    successRate: total > 0 ? (successful / total) * 100 : 100,
    avgLatency: Math.round(row.avg_latency || 0),
    totalDeliveries: total,
    failedDeliveries: total - successful,
    lastDelivery: row.last_delivery,
  };
}

/**
 * Helper: Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
