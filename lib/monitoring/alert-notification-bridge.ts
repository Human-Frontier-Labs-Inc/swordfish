/**
 * Alert-Notification Bridge
 *
 * Wires the AlertManager to the database-backed notification system.
 * Stores alerts in the notifications table and sends notifications
 * based on tenant-specific configuration.
 */

import { sql } from '../db';
import type { Alert, AlertSeverityType } from './alerts';
import { AlertSeverity } from './alerts';
import type { NotificationChannel } from '../ato/notifications';
import { NotificationService } from '../ato/notifications';

// ============================================================================
// Types
// ============================================================================

export interface NotificationConfig {
  id: string;
  tenantId: string;
  channel: NotificationChannel;
  enabled: boolean;
  types: string[];
  destination: string;
  minSeverity: AlertSeverityType;
  createdAt: Date;
}

export interface StoredNotification {
  id: string;
  tenantId: string;
  type: string;
  title: string;
  message: string;
  severity: AlertSeverityType;
  resourceType?: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
  read: boolean;
  createdAt: Date;
}

export interface AlertBridgeConfig {
  /** Default notification channels when no tenant config exists */
  defaultChannels?: NotificationChannel[];
  /** Enable database storage of alerts */
  storeInDatabase?: boolean;
  /** Enable external notification delivery */
  sendNotifications?: boolean;
  /** Log notification activities */
  logActivities?: boolean;
}

const DEFAULT_BRIDGE_CONFIG: Required<AlertBridgeConfig> = {
  defaultChannels: ['email'],
  storeInDatabase: true,
  sendNotifications: true,
  logActivities: true,
};

// ============================================================================
// Notification Config Helpers
// ============================================================================

/**
 * Severity priority mapping (higher = more severe)
 */
const SEVERITY_PRIORITY: Record<string, number> = {
  info: 1,
  warning: 2,
  critical: 3,
};

/**
 * Check if alert severity meets minimum threshold
 */
function meetsMinSeverity(alertSeverity: AlertSeverityType, minSeverity: AlertSeverityType): boolean {
  return SEVERITY_PRIORITY[alertSeverity] >= SEVERITY_PRIORITY[minSeverity];
}

/**
 * Get notification configs for a tenant
 */
export async function getNotificationConfigs(tenantId: string): Promise<NotificationConfig[]> {
  try {
    const results = await sql`
      SELECT
        id,
        tenant_id as "tenantId",
        channel,
        enabled,
        types,
        destination,
        min_severity as "minSeverity",
        created_at as "createdAt"
      FROM notification_configs
      WHERE tenant_id = ${tenantId}
        AND enabled = true
    `;
    return results as NotificationConfig[];
  } catch (error) {
    console.warn('[alert-bridge] Failed to fetch notification configs:', error);
    return [];
  }
}

/**
 * Get notification config for a specific channel
 */
export async function getNotificationConfigByChannel(
  tenantId: string,
  channel: NotificationChannel
): Promise<NotificationConfig | null> {
  try {
    const results = await sql`
      SELECT
        id,
        tenant_id as "tenantId",
        channel,
        enabled,
        types,
        destination,
        min_severity as "minSeverity",
        created_at as "createdAt"
      FROM notification_configs
      WHERE tenant_id = ${tenantId}
        AND channel = ${channel}
        AND enabled = true
      LIMIT 1
    `;
    return results.length > 0 ? (results[0] as NotificationConfig) : null;
  } catch (error) {
    console.warn('[alert-bridge] Failed to fetch notification config:', error);
    return null;
  }
}

/**
 * Create or update notification config
 */
export async function upsertNotificationConfig(
  tenantId: string,
  config: Omit<NotificationConfig, 'id' | 'tenantId' | 'createdAt'>
): Promise<NotificationConfig | null> {
  try {
    const results = await sql`
      INSERT INTO notification_configs (tenant_id, channel, enabled, types, destination, min_severity)
      VALUES (${tenantId}, ${config.channel}, ${config.enabled}, ${config.types}, ${config.destination}, ${config.minSeverity})
      ON CONFLICT (tenant_id, channel)
      DO UPDATE SET
        enabled = EXCLUDED.enabled,
        types = EXCLUDED.types,
        destination = EXCLUDED.destination,
        min_severity = EXCLUDED.min_severity
      RETURNING
        id,
        tenant_id as "tenantId",
        channel,
        enabled,
        types,
        destination,
        min_severity as "minSeverity",
        created_at as "createdAt"
    `;
    return results.length > 0 ? (results[0] as NotificationConfig) : null;
  } catch (error) {
    console.warn('[alert-bridge] Failed to upsert notification config:', error);
    return null;
  }
}

// ============================================================================
// Database Notification Storage
// ============================================================================

/**
 * Store an alert as a notification in the database
 */
export async function storeNotification(
  tenantId: string,
  alert: Alert
): Promise<StoredNotification | null> {
  try {
    const results = await sql`
      INSERT INTO notifications (tenant_id, type, title, message, severity, resource_type, resource_id, metadata)
      VALUES (
        ${tenantId},
        ${'alert'},
        ${alert.ruleName},
        ${formatAlertMessage(alert)},
        ${alert.severity},
        ${'alert_rule'},
        ${alert.ruleId},
        ${JSON.stringify({
          status: alert.status,
          metric: alert.metric,
          value: alert.value,
          threshold: alert.threshold,
          timestamp: alert.timestamp,
        })}
      )
      RETURNING
        id,
        tenant_id as "tenantId",
        type,
        title,
        message,
        severity,
        resource_type as "resourceType",
        resource_id as "resourceId",
        metadata,
        read,
        created_at as "createdAt"
    `;
    return results.length > 0 ? (results[0] as StoredNotification) : null;
  } catch (error) {
    console.warn('[alert-bridge] Failed to store notification:', error);
    return null;
  }
}

/**
 * Format alert into a human-readable message
 */
function formatAlertMessage(alert: Alert): string {
  if (alert.status === 'resolved') {
    return `Alert resolved: ${alert.ruleName}`;
  }

  const parts = [`Alert triggered: ${alert.ruleName}`];

  if (alert.metric && alert.value !== undefined && alert.threshold !== undefined) {
    parts.push(`${alert.metric} = ${alert.value} (threshold: ${alert.threshold})`);
  }

  return parts.join('. ');
}

/**
 * Get unread notifications for a tenant
 */
export async function getUnreadNotifications(
  tenantId: string,
  limit: number = 50
): Promise<StoredNotification[]> {
  try {
    const results = await sql`
      SELECT
        id,
        tenant_id as "tenantId",
        type,
        title,
        message,
        severity,
        resource_type as "resourceType",
        resource_id as "resourceId",
        metadata,
        read,
        created_at as "createdAt"
      FROM notifications
      WHERE tenant_id = ${tenantId}
        AND read = false
      ORDER BY created_at DESC
      LIMIT ${limit}
    `;
    return results as StoredNotification[];
  } catch (error) {
    console.warn('[alert-bridge] Failed to fetch unread notifications:', error);
    return [];
  }
}

/**
 * Mark notifications as read
 */
export async function markNotificationsRead(
  tenantId: string,
  notificationIds: string[]
): Promise<number> {
  try {
    const result = await sql`
      UPDATE notifications
      SET read = true
      WHERE tenant_id = ${tenantId}
        AND id = ANY(${notificationIds}::uuid[])
    `;
    return (result as unknown as { count: number }).count ?? notificationIds.length;
  } catch (error) {
    console.warn('[alert-bridge] Failed to mark notifications as read:', error);
    return 0;
  }
}

// ============================================================================
// Alert Notification Bridge
// ============================================================================

/**
 * Alert Notification Bridge
 *
 * Bridges the AlertManager to the database notification system
 * and external notification channels.
 */
export class AlertNotificationBridge {
  private config: Required<AlertBridgeConfig>;
  private notificationService: NotificationService;
  private tenantId: string | null = null;

  constructor(config: AlertBridgeConfig = {}) {
    this.config = { ...DEFAULT_BRIDGE_CONFIG, ...config };
    this.notificationService = new NotificationService({
      defaultChannels: this.config.defaultChannels,
    });
  }

  /**
   * Set the current tenant context
   */
  setTenantContext(tenantId: string): void {
    this.tenantId = tenantId;
  }

  /**
   * Clear tenant context
   */
  clearTenantContext(): void {
    this.tenantId = null;
  }

  /**
   * Handle an alert - main entry point for alert processing
   */
  async handleAlert(alert: Alert, tenantId?: string): Promise<void> {
    const effectiveTenantId = tenantId ?? this.tenantId;

    if (!effectiveTenantId) {
      if (this.config.logActivities) {
        console.warn('[alert-bridge] No tenant context for alert:', alert.ruleName);
      }
      return;
    }

    try {
      // Store in database
      if (this.config.storeInDatabase) {
        await storeNotification(effectiveTenantId, alert);
        if (this.config.logActivities) {
          console.info(`[alert-bridge] Stored alert notification for tenant ${effectiveTenantId}: ${alert.ruleName}`);
        }
      }

      // Send external notifications
      if (this.config.sendNotifications) {
        await this.sendNotifications(effectiveTenantId, alert);
      }
    } catch (error) {
      console.error('[alert-bridge] Failed to handle alert:', error);
    }
  }

  /**
   * Send notifications based on tenant config
   */
  private async sendNotifications(tenantId: string, alert: Alert): Promise<void> {
    const configs = await getNotificationConfigs(tenantId);

    // If no configs, use defaults
    if (configs.length === 0) {
      if (this.config.logActivities) {
        console.info(`[alert-bridge] No notification configs for tenant ${tenantId}, using defaults`);
      }
      // Still send to default channels for critical alerts
      if (alert.severity === AlertSeverity.CRITICAL) {
        await this.notificationService.sendToAdmin(
          `[${alert.severity.toUpperCase()}] ${alert.ruleName}`,
          formatAlertMessage(alert),
          { priority: 'urgent' }
        );
      }
      return;
    }

    // Send to each configured channel that meets the severity threshold
    for (const config of configs) {
      // Check if alert type is in allowed types (or if types is empty = all types)
      if (config.types.length > 0 && !config.types.includes('alert')) {
        continue;
      }

      // Check severity threshold
      if (!meetsMinSeverity(alert.severity, config.minSeverity)) {
        continue;
      }

      try {
        await this.sendToChannel(config, alert);
        if (this.config.logActivities) {
          console.info(`[alert-bridge] Sent alert to ${config.channel} for tenant ${tenantId}`);
        }
      } catch (error) {
        console.warn(`[alert-bridge] Failed to send to ${config.channel}:`, error);
      }
    }
  }

  /**
   * Send notification to a specific channel
   */
  private async sendToChannel(config: NotificationConfig, alert: Alert): Promise<void> {
    const subject = `[${alert.severity.toUpperCase()}] ${alert.ruleName}`;
    const body = formatAlertMessage(alert);
    const priority = alert.severity === AlertSeverity.CRITICAL ? 'urgent' :
                     alert.severity === AlertSeverity.WARNING ? 'high' : 'normal';

    switch (config.channel) {
      case 'email':
        await this.notificationService.sendToUser(
          { email: config.destination },
          subject,
          body,
          { priority: priority as 'low' | 'normal' | 'high' | 'urgent' }
        );
        break;

      case 'slack':
        await this.sendSlackNotification(config.destination, alert);
        break;

      case 'webhook':
        await this.sendWebhookNotification(config.destination, alert);
        break;

      case 'pagerduty':
        if (alert.severity === AlertSeverity.CRITICAL) {
          await this.sendPagerDutyNotification(config.destination, alert);
        }
        break;
    }
  }

  /**
   * Send Slack notification
   */
  private async sendSlackNotification(webhookUrl: string, alert: Alert): Promise<void> {
    const color = alert.severity === AlertSeverity.CRITICAL ? '#FF0000' :
                  alert.severity === AlertSeverity.WARNING ? '#FFA500' : '#36A64F';
    const emoji = alert.status === 'firing' ? '🚨' : '✅';

    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attachments: [{
            color,
            title: `${emoji} ${alert.ruleName}`,
            text: formatAlertMessage(alert),
            fields: [
              { title: 'Severity', value: alert.severity, short: true },
              { title: 'Status', value: alert.status, short: true },
              ...(alert.metric ? [{ title: 'Metric', value: alert.metric, short: true }] : []),
              ...(alert.value !== undefined ? [{ title: 'Value', value: String(alert.value), short: true }] : []),
            ],
            ts: Math.floor(new Date(alert.timestamp).getTime() / 1000),
          }],
        }),
      });
    } catch (error) {
      console.warn('[alert-bridge] Failed to send Slack notification:', error);
    }
  }

  /**
   * Send webhook notification
   */
  private async sendWebhookNotification(webhookUrl: string, alert: Alert): Promise<void> {
    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'alert',
          alert,
          timestamp: new Date().toISOString(),
        }),
      });
    } catch (error) {
      console.warn('[alert-bridge] Failed to send webhook notification:', error);
    }
  }

  /**
   * Send PagerDuty notification
   */
  private async sendPagerDutyNotification(routingKey: string, alert: Alert): Promise<void> {
    try {
      await fetch('https://events.pagerduty.com/v2/enqueue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          routing_key: routingKey,
          event_action: alert.status === 'firing' ? 'trigger' : 'resolve',
          dedup_key: alert.ruleId,
          payload: {
            summary: alert.ruleName,
            severity: alert.severity === AlertSeverity.CRITICAL ? 'critical' : 'warning',
            source: 'swordfish',
            custom_details: {
              metric: alert.metric,
              value: alert.value,
              threshold: alert.threshold,
            },
          },
        }),
      });
    } catch (error) {
      console.warn('[alert-bridge] Failed to send PagerDuty notification:', error);
    }
  }

  /**
   * Create an alert notifier function for use with AlertManager
   */
  createNotifier(tenantId?: string): (alert: Alert) => void {
    return (alert: Alert) => {
      // Fire and forget - don't block the alert manager
      this.handleAlert(alert, tenantId).catch((error) => {
        console.error('[alert-bridge] Error in async notifier:', error);
      });
    };
  }
}

/**
 * Create an alert notification bridge with tenant context
 */
export function createAlertBridge(
  tenantId: string,
  config?: AlertBridgeConfig
): AlertNotificationBridge {
  const bridge = new AlertNotificationBridge(config);
  bridge.setTenantContext(tenantId);
  return bridge;
}

/**
 * Default singleton bridge instance
 */
let defaultBridge: AlertNotificationBridge | null = null;

/**
 * Get or create default bridge instance
 */
export function getAlertBridge(config?: AlertBridgeConfig): AlertNotificationBridge {
  if (!defaultBridge) {
    defaultBridge = new AlertNotificationBridge(config);
  }
  return defaultBridge;
}
