/**
 * Notification Service
 * Handles admin notifications for threats and security events
 */

import { sql } from '@/lib/db';

export type NotificationType =
  | 'threat_detected'
  | 'threat_quarantined'
  | 'threat_released'
  | 'policy_violation'
  | 'integration_error'
  | 'daily_summary'
  | 'weekly_report';

export type NotificationChannel = 'email' | 'slack' | 'webhook' | 'in_app';

export interface NotificationConfig {
  id: string;
  tenantId: string;
  channel: NotificationChannel;
  enabled: boolean;
  types: NotificationType[];
  destination: string; // Email address, Slack webhook, or webhook URL
  minSeverity: 'info' | 'warning' | 'critical';
  createdAt: Date;
}

export interface Notification {
  id: string;
  tenantId: string;
  type: NotificationType;
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'critical';
  resourceType?: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
  read: boolean;
  createdAt: Date;
}

// Guard against legacy schema limits in production (VARCHAR(100) in some envs)
function truncateValue(value: string | null | undefined, maxLength: number): string | null {
  if (!value) return null;
  return value.length > maxLength ? value.slice(0, maxLength - 3) + '...' : value;
}

/**
 * Create and send a notification
 */
export async function sendNotification(params: {
  tenantId: string;
  type: NotificationType;
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'critical';
  resourceType?: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
}): Promise<string> {
  const { tenantId, type, title, message, severity, resourceType, resourceId, metadata } = params;

  const safeType = truncateValue(type, 100) || 'unknown';
  const safeResourceType = truncateValue(resourceType, 100);
  const safeResourceId = truncateValue(resourceId, 100);

  // Store in-app notification
  const result = await sql`
    INSERT INTO notifications (
      tenant_id, type, title, message, severity,
      resource_type, resource_id, metadata, read, created_at
    ) VALUES (
      ${tenantId}, ${safeType}, ${title}, ${message}, ${severity},
      ${safeResourceType || null}, ${safeResourceId || null},
      ${metadata ? JSON.stringify(metadata) : null}, false, NOW()
    )
    RETURNING id
  `;

  const notificationId = result[0].id as string;

  // Get notification configs for this tenant
  const configs = await getNotificationConfigs(tenantId);

  // Send to enabled channels
  for (const config of configs) {
    if (!config.enabled) continue;
    if (!config.types.includes(type)) continue;
    if (!meetsMinSeverity(severity, config.minSeverity)) continue;

    try {
      switch (config.channel) {
        case 'email':
          await sendEmailNotification(config.destination, title, message, severity);
          break;
        case 'slack':
          await sendSlackNotification(config.destination, title, message, severity);
          break;
        case 'webhook':
          await sendWebhookNotification(config.destination, {
            id: notificationId,
            type,
            title,
            message,
            severity,
            resourceType,
            resourceId,
            metadata,
            timestamp: new Date().toISOString(),
          });
          break;
        // in_app is already stored above
      }
    } catch (error) {
      console.error(`Failed to send ${config.channel} notification:`, error);
    }
  }

  return notificationId;
}

/**
 * Send threat detection notification
 */
export async function notifyThreatDetected(params: {
  tenantId: string;
  messageId: string;
  subject: string;
  sender: string;
  verdict: string;
  score: number;
  action: 'quarantine' | 'block' | 'suspicious';
}): Promise<void> {
  const { tenantId, messageId, subject, sender, verdict, score, action } = params;

  const severity = score >= 80 ? 'critical' : score >= 50 ? 'warning' : 'info';

  const actionText = {
    quarantine: 'has been quarantined',
    block: 'has been blocked',
    suspicious: 'has been flagged as suspicious',
  }[action];

  await sendNotification({
    tenantId,
    type: 'threat_quarantined',
    title: `Threat Detected: ${verdict}`,
    message: `An email from ${sender} ${actionText}. Subject: "${subject}". Score: ${score}/100`,
    severity,
    resourceType: 'threat',
    resourceId: messageId,
    metadata: { sender, subject, verdict, score, action },
  });
}

/**
 * Get notification configs for a tenant
 */
export async function getNotificationConfigs(tenantId: string): Promise<NotificationConfig[]> {
  const configs = await sql`
    SELECT * FROM notification_configs
    WHERE tenant_id = ${tenantId}
    ORDER BY created_at DESC
  `;

  return configs.map((c: Record<string, unknown>) => ({
    id: c.id as string,
    tenantId: c.tenant_id as string,
    channel: c.channel as NotificationChannel,
    enabled: c.enabled as boolean,
    types: (c.types as NotificationType[]) || [],
    destination: c.destination as string,
    minSeverity: (c.min_severity as 'info' | 'warning' | 'critical') || 'warning',
    createdAt: new Date(c.created_at as string),
  }));
}

/**
 * Create or update a notification config
 */
export async function upsertNotificationConfig(config: {
  tenantId: string;
  channel: NotificationChannel;
  enabled: boolean;
  types: NotificationType[];
  destination: string;
  minSeverity: 'info' | 'warning' | 'critical';
}): Promise<string> {
  const { tenantId, channel, enabled, types, destination, minSeverity } = config;

  const result = await sql`
    INSERT INTO notification_configs (
      tenant_id, channel, enabled, types, destination, min_severity, created_at
    ) VALUES (
      ${tenantId}, ${channel}, ${enabled}, ${types}, ${destination}, ${minSeverity}, NOW()
    )
    ON CONFLICT (tenant_id, channel)
    DO UPDATE SET
      enabled = ${enabled},
      types = ${types},
      destination = ${destination},
      min_severity = ${minSeverity}
    RETURNING id
  `;

  return result[0].id as string;
}

/**
 * Get in-app notifications for a tenant
 */
export async function getNotifications(
  tenantId: string,
  options: { unreadOnly?: boolean; limit?: number; offset?: number } = {}
): Promise<Notification[]> {
  const { unreadOnly = false, limit = 50, offset = 0 } = options;

  let notifications;
  if (unreadOnly) {
    notifications = await sql`
      SELECT * FROM notifications
      WHERE tenant_id = ${tenantId}
      AND read = false
      ORDER BY created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;
  } else {
    notifications = await sql`
      SELECT * FROM notifications
      WHERE tenant_id = ${tenantId}
      ORDER BY created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;
  }

  return notifications.map((n: Record<string, unknown>) => ({
    id: n.id as string,
    tenantId: n.tenant_id as string,
    type: n.type as NotificationType,
    title: n.title as string,
    message: n.message as string,
    severity: n.severity as 'info' | 'warning' | 'critical',
    resourceType: n.resource_type as string | undefined,
    resourceId: n.resource_id as string | undefined,
    metadata: n.metadata as Record<string, unknown> | undefined,
    read: n.read as boolean,
    createdAt: new Date(n.created_at as string),
  }));
}

/**
 * Mark notifications as read
 */
export async function markNotificationsRead(
  tenantId: string,
  notificationIds: string[]
): Promise<void> {
  if (notificationIds.length === 0) return;

  await sql`
    UPDATE notifications
    SET read = true
    WHERE tenant_id = ${tenantId}
    AND id = ANY(${notificationIds})
  `;
}

/**
 * Get unread notification count
 */
export async function getUnreadCount(tenantId: string): Promise<number> {
  const result = await sql`
    SELECT COUNT(*) as count
    FROM notifications
    WHERE tenant_id = ${tenantId}
    AND read = false
  `;
  return Number(result[0].count) || 0;
}

// ============================================
// Channel-specific senders
// ============================================

async function sendEmailNotification(
  to: string,
  title: string,
  message: string,
  severity: 'info' | 'warning' | 'critical'
): Promise<void> {
  // Use environment-configured email service
  const emailProvider = process.env.EMAIL_PROVIDER || 'resend';

  if (emailProvider === 'resend' && process.env.RESEND_API_KEY) {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: process.env.EMAIL_FROM || 'Swordfish <alerts@swordfish.security>',
        to: [to],
        subject: `[${severity.toUpperCase()}] ${title}`,
        text: message,
        html: `
          <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: ${getSeverityColor(severity)}; color: white; padding: 16px; border-radius: 8px 8px 0 0;">
              <h1 style="margin: 0; font-size: 18px;">${title}</h1>
            </div>
            <div style="padding: 16px; background: #f9fafb; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
              <p style="margin: 0; color: #374151;">${message}</p>
            </div>
            <p style="color: #6b7280; font-size: 12px; margin-top: 16px;">
              Swordfish Email Security
            </p>
          </div>
        `,
      }),
    });
  }
}

async function sendSlackNotification(
  webhookUrl: string,
  title: string,
  message: string,
  severity: 'info' | 'warning' | 'critical'
): Promise<void> {
  const emoji = {
    info: ':information_source:',
    warning: ':warning:',
    critical: ':rotating_light:',
  }[severity];

  await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      attachments: [
        {
          color: getSeverityColor(severity),
          blocks: [
            {
              type: 'header',
              text: {
                type: 'plain_text',
                text: `${emoji} ${title}`,
                emoji: true,
              },
            },
            {
              type: 'section',
              text: {
                type: 'mrkdwn',
                text: message,
              },
            },
            {
              type: 'context',
              elements: [
                {
                  type: 'mrkdwn',
                  text: `Swordfish Email Security | ${new Date().toISOString()}`,
                },
              ],
            },
          ],
        },
      ],
    }),
  });
}

async function sendWebhookNotification(
  webhookUrl: string,
  payload: Record<string, unknown>
): Promise<void> {
  await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...payload,
      source: 'swordfish',
      version: '1.0',
    }),
  });
}

function getSeverityColor(severity: 'info' | 'warning' | 'critical'): string {
  return {
    info: '#3b82f6',
    warning: '#f59e0b',
    critical: '#ef4444',
  }[severity];
}

function meetsMinSeverity(
  actual: 'info' | 'warning' | 'critical',
  minimum: 'info' | 'warning' | 'critical'
): boolean {
  const levels = { info: 0, warning: 1, critical: 2 };
  return levels[actual] >= levels[minimum];
}

// ============================================
// Threat Notification Wrapper (for webhook)
// ============================================

export interface ThreatNotificationPayload {
  type: 'threat_detected' | 'threat_quarantined' | 'threat_blocked' | 'threat_released';
  severity: 'info' | 'warning' | 'critical';
  title: string;
  message: string;
  metadata?: Record<string, unknown>;
}

/**
 * Send threat notification (wrapper for webhook compatibility)
 */
export async function sendThreatNotification(
  tenantId: string,
  notification: ThreatNotificationPayload
): Promise<void> {
  await sendNotification({
    tenantId,
    type: notification.type === 'threat_blocked' ? 'threat_quarantined' : notification.type,
    title: notification.title,
    message: notification.message,
    severity: notification.severity,
    resourceType: 'threat',
    resourceId: notification.metadata?.messageId as string,
    metadata: notification.metadata,
  });
}
