/**
 * Alert Management Module
 *
 * Defines alert rules, evaluates conditions, and manages alert state.
 */

/**
 * Alert severity levels
 */
export const AlertSeverity = {
  INFO: 'info',
  WARNING: 'warning',
  CRITICAL: 'critical',
} as const;

export type AlertSeverityType = (typeof AlertSeverity)[keyof typeof AlertSeverity];

/**
 * Alert condition operators
 */
type Operator = 'gt' | 'lt' | 'eq' | 'gte' | 'lte';

/**
 * Alert condition
 */
export interface AlertCondition {
  metric: string;
  operator: Operator;
  threshold: number;
  window: string;
}

/**
 * Alert action configuration
 */
export interface AlertAction {
  type: 'email' | 'webhook' | 'slack' | 'pagerduty';
  target: string;
  template?: string;
}

/**
 * Extended alert condition (used by API)
 */
export interface ExtendedAlertCondition {
  type: string;
  metric: string;
  operator: Operator;
  value: number;
  window?: string;
}

/**
 * Alert rule definition
 */
export interface AlertRule {
  id: string;
  name: string;
  description?: string;
  condition?: AlertCondition | ExtendedAlertCondition;
  conditions?: AlertCondition[];
  severity?: AlertSeverityType;
  cooldown?: string;
  cooldownMinutes?: number;
  actions?: AlertAction[];
  isActive?: boolean;
}

/**
 * Alert notification
 */
export interface Alert {
  ruleId: string;
  ruleName: string;
  severity: AlertSeverityType;
  status: 'firing' | 'resolved';
  timestamp: string;
  value?: number;
  threshold?: number;
  metric?: string;
}

/**
 * Alert notifier function
 */
type AlertNotifier = (alert: Alert) => void;

/**
 * Alert manager configuration
 */
interface AlertManagerConfig {
  notify: AlertNotifier;
}

/**
 * Parse duration string to milliseconds
 */
function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)(s|m|h|d)$/);
  if (!match) return 0;

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's': return value * 1000;
    case 'm': return value * 60 * 1000;
    case 'h': return value * 60 * 60 * 1000;
    case 'd': return value * 24 * 60 * 60 * 1000;
    default: return 0;
  }
}

/**
 * Alert manager class
 */
export class AlertManager {
  private rules: AlertRule[] = [];
  private notify: AlertNotifier;
  private activeAlerts: Map<string, Alert> = new Map();
  private lastFired: Map<string, number> = new Map();

  constructor(config: AlertManagerConfig) {
    this.notify = config.notify;
  }

  registerRule(rule: AlertRule): void {
    this.rules.push(rule);
  }

  getRules(): AlertRule[] {
    return [...this.rules];
  }

  getActiveAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values());
  }

  private evaluateCondition(condition: AlertCondition | ExtendedAlertCondition, metrics: Record<string, number>): boolean {
    const value = metrics[condition.metric];
    if (value === undefined) return false;

    // Get threshold from either condition type
    const threshold = 'threshold' in condition ? condition.threshold : condition.value;

    switch (condition.operator) {
      case 'gt': return value > threshold;
      case 'lt': return value < threshold;
      case 'eq': return value === threshold;
      case 'gte': return value >= threshold;
      case 'lte': return value <= threshold;
      default: return false;
    }
  }

  evaluate(metrics: Record<string, number>): void {
    const now = Date.now();

    for (const rule of this.rules) {
      const conditions = rule.conditions || (rule.condition ? [rule.condition] : []);
      const isTriggered = conditions.every(c => this.evaluateCondition(c, metrics));
      const isActive = this.activeAlerts.has(rule.id);

      if (isTriggered && !isActive) {
        // Check cooldown
        const lastFiredTime = this.lastFired.get(rule.id) || 0;
        const cooldownMs = rule.cooldown ? parseDuration(rule.cooldown) : 0;

        if (now - lastFiredTime < cooldownMs) {
          continue;
        }

        const condition = conditions[0];
        const conditionThreshold = condition ? ('threshold' in condition ? condition.threshold : condition.value) : undefined;
        const alert: Alert = {
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity || AlertSeverity.WARNING,
          status: 'firing',
          timestamp: new Date().toISOString(),
          value: condition ? metrics[condition.metric] : undefined,
          threshold: conditionThreshold,
          metric: condition?.metric,
        };

        this.activeAlerts.set(rule.id, alert);
        this.lastFired.set(rule.id, now);
        this.notify(alert);
      } else if (!isTriggered && isActive) {
        const alert: Alert = {
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity || AlertSeverity.WARNING,
          status: 'resolved',
          timestamp: new Date().toISOString(),
        };

        this.activeAlerts.delete(rule.id);
        this.notify(alert);
      }
    }
  }

  getPredefinedRules(): AlertRule[] {
    return [
      {
        id: 'high-threat-rate',
        name: 'High Threat Detection Rate',
        condition: { metric: 'threats_detected_total', operator: 'gt', threshold: 100, window: '5m' },
        severity: AlertSeverity.WARNING,
      },
      {
        id: 'integration-errors',
        name: 'Integration Errors',
        condition: { metric: 'integration_errors_total', operator: 'gt', threshold: 10, window: '5m' },
        severity: AlertSeverity.CRITICAL,
      },
      {
        id: 'high-latency',
        name: 'High API Latency',
        condition: { metric: 'api_latency_p99', operator: 'gt', threshold: 5, window: '5m' },
        severity: AlertSeverity.WARNING,
      },
    ];
  }
}

export function createAlertManager(config: AlertManagerConfig): AlertManager {
  return new AlertManager(config);
}

/**
 * System-defined alert rules that apply to all tenants
 */
export const SYSTEM_ALERT_RULES: AlertRule[] = [
  {
    id: 'system-high-threat-rate',
    name: 'High Threat Detection Rate',
    condition: { metric: 'threats_detected_total', operator: 'gt', threshold: 100, window: '5m' },
    severity: AlertSeverity.WARNING,
  },
  {
    id: 'system-integration-errors',
    name: 'Integration Errors',
    condition: { metric: 'integration_errors_total', operator: 'gt', threshold: 10, window: '5m' },
    severity: AlertSeverity.CRITICAL,
  },
  {
    id: 'system-high-latency',
    name: 'High API Latency',
    condition: { metric: 'api_latency_p99', operator: 'gt', threshold: 5000, window: '5m' },
    severity: AlertSeverity.WARNING,
  },
];

/**
 * In-memory storage for alert rules and active alerts (per tenant)
 * In production, this would be backed by a database
 */
const alertRulesStore = new Map<string, AlertRule[]>();
const activeAlertsStore = new Map<string, Alert[]>();

/**
 * Create a new alert rule for a tenant
 */
export async function createAlertRule(
  tenantId: string,
  rule: Omit<AlertRule, 'id'>
): Promise<AlertRule> {
  const id = `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const newRule: AlertRule = { id, ...rule };

  const tenantRules = alertRulesStore.get(tenantId) || [];
  tenantRules.push(newRule);
  alertRulesStore.set(tenantId, tenantRules);

  return newRule;
}

/**
 * Get all alert rules for a tenant
 */
export async function getAlertRules(tenantId: string): Promise<AlertRule[]> {
  return alertRulesStore.get(tenantId) || [];
}

/**
 * Update an existing alert rule
 */
export async function updateAlertRule(
  ruleId: string,
  tenantId: string,
  updates: Partial<AlertRule>
): Promise<boolean> {
  const tenantRules = alertRulesStore.get(tenantId) || [];
  const ruleIndex = tenantRules.findIndex(r => r.id === ruleId);

  if (ruleIndex === -1) return false;

  tenantRules[ruleIndex] = { ...tenantRules[ruleIndex], ...updates };
  alertRulesStore.set(tenantId, tenantRules);

  return true;
}

/**
 * Delete an alert rule
 */
export async function deleteAlertRule(ruleId: string, tenantId: string): Promise<boolean> {
  const tenantRules = alertRulesStore.get(tenantId) || [];
  const filtered = tenantRules.filter(r => r.id !== ruleId);

  if (filtered.length === tenantRules.length) return false;

  alertRulesStore.set(tenantId, filtered);
  return true;
}

/**
 * Get active alerts for a tenant
 */
export async function getActiveAlerts(tenantId: string): Promise<Alert[]> {
  return activeAlertsStore.get(tenantId) || [];
}

/**
 * Acknowledge an active alert
 */
export async function acknowledgeAlert(
  alertId: string,
  tenantId: string,
  acknowledgedBy: string
): Promise<boolean> {
  const tenantAlerts = activeAlertsStore.get(tenantId) || [];
  const alertIndex = tenantAlerts.findIndex(a => a.ruleId === alertId);

  if (alertIndex === -1) return false;

  // Mark as acknowledged (in a real system, this would update the alert status)
  return true;
}

/**
 * Resolve an active alert
 */
export async function resolveAlert(alertId: string, tenantId: string): Promise<boolean> {
  const tenantAlerts = activeAlertsStore.get(tenantId) || [];
  const filtered = tenantAlerts.filter(a => a.ruleId !== alertId);

  if (filtered.length === tenantAlerts.length) return false;

  activeAlertsStore.set(tenantId, filtered);
  return true;
}
