/**
 * Alert Configuration System
 *
 * Define, manage, and trigger alerts based on system conditions
 */

import { sql } from '@/lib/db';
import { nanoid } from 'nanoid';

export interface AlertRule {
  id: string;
  tenantId: string;
  name: string;
  description: string;
  condition: AlertCondition;
  actions: AlertAction[];
  isActive: boolean;
  cooldownMinutes: number;
  lastTriggeredAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface AlertCondition {
  type: 'threshold' | 'anomaly' | 'pattern';
  metric: string;
  operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  value: number;
  windowMinutes?: number;
}

export interface AlertAction {
  type: 'email' | 'webhook' | 'slack' | 'pagerduty';
  config: Record<string, string>;
}

export interface Alert {
  id: string;
  ruleId: string;
  tenantId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  message: string;
  metadata: Record<string, unknown>;
  status: 'active' | 'acknowledged' | 'resolved';
  triggeredAt: Date;
  acknowledgedAt?: Date;
  resolvedAt?: Date;
  acknowledgedBy?: string;
}

// Predefined alert rules
export const SYSTEM_ALERT_RULES: Omit<AlertRule, 'id' | 'tenantId' | 'createdAt' | 'updatedAt'>[] = [
  {
    name: 'High Threat Volume',
    description: 'Alert when threat volume exceeds normal levels',
    condition: {
      type: 'threshold',
      metric: 'threats_detected',
      operator: 'gt',
      value: 100,
      windowMinutes: 60,
    },
    actions: [{ type: 'email', config: { template: 'high_threat_volume' } }],
    isActive: true,
    cooldownMinutes: 60,
  },
  {
    name: 'Critical Threat Detected',
    description: 'Alert on high-confidence threats',
    condition: {
      type: 'threshold',
      metric: 'threat_confidence',
      operator: 'gte',
      value: 95,
    },
    actions: [
      { type: 'email', config: { template: 'critical_threat' } },
      { type: 'webhook', config: {} },
    ],
    isActive: true,
    cooldownMinutes: 0,
  },
  {
    name: 'Integration Error',
    description: 'Alert when an integration fails to sync',
    condition: {
      type: 'pattern',
      metric: 'integration_errors',
      operator: 'gt',
      value: 3,
      windowMinutes: 30,
    },
    actions: [{ type: 'email', config: { template: 'integration_error' } }],
    isActive: true,
    cooldownMinutes: 30,
  },
  {
    name: 'High False Positive Rate',
    description: 'Alert when false positive rate is elevated',
    condition: {
      type: 'threshold',
      metric: 'false_positive_rate',
      operator: 'gt',
      value: 10,
      windowMinutes: 1440,
    },
    actions: [{ type: 'email', config: { template: 'high_fp_rate' } }],
    isActive: true,
    cooldownMinutes: 1440,
  },
  {
    name: 'Email Processing Delay',
    description: 'Alert when email processing time exceeds SLA',
    condition: {
      type: 'threshold',
      metric: 'processing_time_p95',
      operator: 'gt',
      value: 5000,
      windowMinutes: 15,
    },
    actions: [{ type: 'email', config: { template: 'processing_delay' } }],
    isActive: true,
    cooldownMinutes: 30,
  },
];

/**
 * Create an alert rule
 */
export async function createAlertRule(
  tenantId: string,
  rule: Omit<AlertRule, 'id' | 'tenantId' | 'createdAt' | 'updatedAt'>
): Promise<AlertRule> {
  const id = nanoid();
  const now = new Date();

  await sql`
    INSERT INTO alert_rules (
      id, tenant_id, name, description, condition, actions,
      is_active, cooldown_minutes, created_at, updated_at
    )
    VALUES (
      ${id},
      ${tenantId},
      ${rule.name},
      ${rule.description},
      ${JSON.stringify(rule.condition)},
      ${JSON.stringify(rule.actions)},
      ${rule.isActive},
      ${rule.cooldownMinutes},
      ${now.toISOString()},
      ${now.toISOString()}
    )
  `;

  return {
    ...rule,
    id,
    tenantId,
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Get alert rules for a tenant
 */
export async function getAlertRules(tenantId: string): Promise<AlertRule[]> {
  const rules = await sql`
    SELECT *
    FROM alert_rules
    WHERE tenant_id = ${tenantId}
    ORDER BY created_at DESC
  `;

  return rules.map((r: Record<string, unknown>) => ({
    id: r.id as string,
    tenantId: r.tenant_id as string,
    name: r.name as string,
    description: r.description as string,
    condition: r.condition as AlertCondition,
    actions: r.actions as AlertAction[],
    isActive: r.is_active as boolean,
    cooldownMinutes: r.cooldown_minutes as number,
    lastTriggeredAt: r.last_triggered_at as Date | undefined,
    createdAt: r.created_at as Date,
    updatedAt: r.updated_at as Date,
  }));
}

/**
 * Update an alert rule
 */
export async function updateAlertRule(
  ruleId: string,
  tenantId: string,
  updates: Partial<AlertRule>
): Promise<boolean> {
  // First fetch the existing rule
  const existing = await sql`
    SELECT * FROM alert_rules WHERE id = ${ruleId} AND tenant_id = ${tenantId}
  `;

  if (existing.length === 0) return false;

  const current = existing[0] as Record<string, unknown>;

  // Merge updates with current values
  const name = updates.name ?? current.name;
  const description = updates.description ?? current.description;
  const condition = updates.condition ? JSON.stringify(updates.condition) : current.condition;
  const actions = updates.actions ? JSON.stringify(updates.actions) : current.actions;
  const isActive = updates.isActive ?? current.is_active;
  const cooldownMinutes = updates.cooldownMinutes ?? current.cooldown_minutes;

  const result = await sql`
    UPDATE alert_rules
    SET
      name = ${name},
      description = ${description},
      condition = ${condition},
      actions = ${actions},
      is_active = ${isActive},
      cooldown_minutes = ${cooldownMinutes},
      updated_at = ${new Date().toISOString()}
    WHERE id = ${ruleId} AND tenant_id = ${tenantId}
    RETURNING id
  `;

  return result.length > 0;
}

/**
 * Delete an alert rule
 */
export async function deleteAlertRule(ruleId: string, tenantId: string): Promise<boolean> {
  const result = await sql`
    DELETE FROM alert_rules
    WHERE id = ${ruleId} AND tenant_id = ${tenantId}
    RETURNING id
  `;
  return result.length > 0;
}

/**
 * Trigger an alert
 */
export async function triggerAlert(
  rule: AlertRule,
  severity: Alert['severity'],
  title: string,
  message: string,
  metadata: Record<string, unknown> = {}
): Promise<Alert> {
  const id = nanoid();
  const now = new Date();

  // Check cooldown
  if (rule.lastTriggeredAt && rule.cooldownMinutes > 0) {
    const cooldownMs = rule.cooldownMinutes * 60 * 1000;
    if (now.getTime() - new Date(rule.lastTriggeredAt).getTime() < cooldownMs) {
      throw new Error('Alert is in cooldown period');
    }
  }

  // Create alert
  await sql`
    INSERT INTO alerts (
      id, rule_id, tenant_id, severity, title, message,
      metadata, status, triggered_at
    )
    VALUES (
      ${id},
      ${rule.id},
      ${rule.tenantId},
      ${severity},
      ${title},
      ${message},
      ${JSON.stringify(metadata)},
      'active',
      ${now.toISOString()}
    )
  `;

  // Update last triggered time
  await sql`
    UPDATE alert_rules
    SET last_triggered_at = ${now.toISOString()}
    WHERE id = ${rule.id}
  `;

  // Execute alert actions
  await executeAlertActions(rule.actions, {
    id,
    ruleId: rule.id,
    tenantId: rule.tenantId,
    severity,
    title,
    message,
    metadata,
    status: 'active',
    triggeredAt: now,
  });

  return {
    id,
    ruleId: rule.id,
    tenantId: rule.tenantId,
    severity,
    title,
    message,
    metadata,
    status: 'active',
    triggeredAt: now,
  };
}

/**
 * Execute alert actions
 */
async function executeAlertActions(actions: AlertAction[], alert: Alert): Promise<void> {
  for (const action of actions) {
    try {
      switch (action.type) {
        case 'email':
          await sendEmailAlert(alert, action.config);
          break;
        case 'webhook':
          await sendWebhookAlert(alert, action.config);
          break;
        case 'slack':
          await sendSlackAlert(alert, action.config);
          break;
        case 'pagerduty':
          await sendPagerDutyAlert(alert, action.config);
          break;
      }
    } catch (error) {
      console.error(`Failed to execute ${action.type} alert action:`, error);
    }
  }
}

async function sendEmailAlert(alert: Alert, config: Record<string, string>): Promise<void> {
  // Would integrate with email service (SendGrid, SES, etc.)
  console.log('Email alert:', alert.title, config);
}

async function sendWebhookAlert(alert: Alert, config: Record<string, string>): Promise<void> {
  const url = config.url;
  if (!url) return;

  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'alert',
        alert: {
          id: alert.id,
          severity: alert.severity,
          title: alert.title,
          message: alert.message,
          triggeredAt: alert.triggeredAt,
          metadata: alert.metadata,
        },
      }),
    });
  } catch (error) {
    console.error('Webhook alert failed:', error);
  }
}

async function sendSlackAlert(alert: Alert, config: Record<string, string>): Promise<void> {
  const webhookUrl = config.webhook_url;
  if (!webhookUrl) return;

  const severityColors: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#2563eb',
    info: '#6b7280',
  };

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        attachments: [{
          color: severityColors[alert.severity],
          title: alert.title,
          text: alert.message,
          fields: [
            { title: 'Severity', value: alert.severity.toUpperCase(), short: true },
            { title: 'Time', value: alert.triggeredAt.toISOString(), short: true },
          ],
        }],
      }),
    });
  } catch (error) {
    console.error('Slack alert failed:', error);
  }
}

async function sendPagerDutyAlert(alert: Alert, config: Record<string, string>): Promise<void> {
  const routingKey = config.routing_key;
  if (!routingKey) return;

  const severityMap: Record<string, string> = {
    critical: 'critical',
    high: 'error',
    medium: 'warning',
    low: 'info',
    info: 'info',
  };

  try {
    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: 'trigger',
        payload: {
          summary: alert.title,
          severity: severityMap[alert.severity],
          source: 'swordfish',
          custom_details: {
            message: alert.message,
            ...alert.metadata,
          },
        },
      }),
    });
  } catch (error) {
    console.error('PagerDuty alert failed:', error);
  }
}

/**
 * Get active alerts for a tenant
 */
export async function getActiveAlerts(tenantId: string): Promise<Alert[]> {
  const alerts = await sql`
    SELECT *
    FROM alerts
    WHERE tenant_id = ${tenantId}
      AND status = 'active'
    ORDER BY triggered_at DESC
    LIMIT 100
  `;

  return alerts.map((a: Record<string, unknown>) => ({
    id: a.id as string,
    ruleId: a.rule_id as string,
    tenantId: a.tenant_id as string,
    severity: a.severity as Alert['severity'],
    title: a.title as string,
    message: a.message as string,
    metadata: (a.metadata as Record<string, unknown>) || {},
    status: a.status as Alert['status'],
    triggeredAt: a.triggered_at as Date,
    acknowledgedAt: a.acknowledged_at as Date | undefined,
    resolvedAt: a.resolved_at as Date | undefined,
    acknowledgedBy: a.acknowledged_by as string | undefined,
  }));
}

/**
 * Acknowledge an alert
 */
export async function acknowledgeAlert(
  alertId: string,
  tenantId: string,
  userId: string
): Promise<boolean> {
  const result = await sql`
    UPDATE alerts
    SET
      status = 'acknowledged',
      acknowledged_at = NOW(),
      acknowledged_by = ${userId}
    WHERE id = ${alertId} AND tenant_id = ${tenantId}
    RETURNING id
  `;
  return result.length > 0;
}

/**
 * Resolve an alert
 */
export async function resolveAlert(alertId: string, tenantId: string): Promise<boolean> {
  const result = await sql`
    UPDATE alerts
    SET
      status = 'resolved',
      resolved_at = NOW()
    WHERE id = ${alertId} AND tenant_id = ${tenantId}
    RETURNING id
  `;
  return result.length > 0;
}
