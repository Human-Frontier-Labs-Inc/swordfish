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
 * Alert rule definition
 */
export interface AlertRule {
  id: string;
  name: string;
  condition?: AlertCondition;
  conditions?: AlertCondition[];
  severity: AlertSeverityType;
  cooldown?: string;
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

  private evaluateCondition(condition: AlertCondition, metrics: Record<string, number>): boolean {
    const value = metrics[condition.metric];
    if (value === undefined) return false;

    switch (condition.operator) {
      case 'gt': return value > condition.threshold;
      case 'lt': return value < condition.threshold;
      case 'eq': return value === condition.threshold;
      case 'gte': return value >= condition.threshold;
      case 'lte': return value <= condition.threshold;
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
        const alert: Alert = {
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          status: 'firing',
          timestamp: new Date().toISOString(),
          value: condition ? metrics[condition.metric] : undefined,
          threshold: condition?.threshold,
          metric: condition?.metric,
        };

        this.activeAlerts.set(rule.id, alert);
        this.lastFired.set(rule.id, now);
        this.notify(alert);
      } else if (!isTriggered && isActive) {
        const alert: Alert = {
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
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
