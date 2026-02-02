/**
 * Observability Setup
 *
 * Unified configuration for metrics, tracing, error tracking, and alerts.
 * Integrates with Prometheus, OpenTelemetry, and external services.
 */

import { MetricsCollector, Counter, Histogram, Gauge } from './metrics';
import { ErrorTracker, WebhookReporter, ConsoleReporter, ErrorEvent } from './error-tracking';
import { Tracer, SpanExporter, SpanData, SpanStatus } from './tracing';
import { AlertManager, Alert, AlertSeverity } from './alerts';
import { AlertNotificationBridge, type AlertBridgeConfig } from './alert-notification-bridge';

/**
 * Observability configuration
 */
export interface ObservabilityConfig {
  serviceName: string;
  environment: string;
  version?: string;

  // Metrics configuration
  metrics?: {
    enabled?: boolean;
    prefix?: string;
    defaultLabels?: Record<string, string>;
  };

  // Tracing configuration
  tracing?: {
    enabled?: boolean;
    sampleRate?: number;
    endpoint?: string;
    headers?: Record<string, string>;
  };

  // Error tracking configuration
  errorTracking?: {
    enabled?: boolean;
    sampleRate?: number;
    dsn?: string; // Sentry-style DSN
  };

  // Alerting configuration
  alerting?: {
    enabled?: boolean;
    webhookUrl?: string;
    slackWebhookUrl?: string;
    pagerDutyKey?: string;
    /** Enable database-backed notifications via AlertNotificationBridge */
    enableDatabaseNotifications?: boolean;
    /** Bridge configuration for database notifications */
    bridgeConfig?: AlertBridgeConfig;
  };
}

/**
 * Application-specific metrics for Swordfish
 */
export interface SwordfishMetrics {
  // Email processing
  emailsProcessed: Counter;
  emailProcessingDuration: Histogram;
  emailsInQueue: Gauge;

  // Threat detection
  threatsDetected: Counter;
  threatDetectionDuration: Histogram;
  verdictDistribution: Counter;

  // Remediation
  remediationActions: Counter;
  remediationDuration: Histogram;
  remediationFailures: Counter;

  // API metrics
  httpRequestsTotal: Counter;
  httpRequestDuration: Histogram;
  httpRequestsInFlight: Gauge;

  // Integration metrics
  integrationCalls: Counter;
  integrationLatency: Histogram;
  integrationErrors: Counter;

  // Database metrics
  dbQueriesTotal: Counter;
  dbQueryDuration: Histogram;
  dbConnectionPoolSize: Gauge;
}

/**
 * Tracing exporter for OpenTelemetry-compatible endpoints
 */
export class OTLPSpanExporter implements SpanExporter {
  private endpoint: string;
  private headers: Record<string, string>;
  private batch: SpanData[] = [];
  private batchSize: number;
  private flushInterval: number;
  private flushTimer?: ReturnType<typeof setTimeout>;

  constructor(config: {
    endpoint: string;
    headers?: Record<string, string>;
    batchSize?: number;
    flushInterval?: number;
  }) {
    this.endpoint = config.endpoint;
    this.headers = config.headers ?? {};
    this.batchSize = config.batchSize ?? 100;
    this.flushInterval = config.flushInterval ?? 5000;
  }

  export(span: SpanData): void {
    this.batch.push(span);

    if (this.batch.length >= this.batchSize) {
      this.flush();
    } else if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.flushInterval);
    }
  }

  async flush(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }

    if (this.batch.length === 0) return;

    const spans = [...this.batch];
    this.batch = [];

    try {
      // Convert to OTLP format
      const payload = {
        resourceSpans: [{
          resource: {
            attributes: [],
          },
          scopeSpans: [{
            scope: { name: 'swordfish' },
            spans: spans.map(s => this.convertToOTLP(s)),
          }],
        }],
      };

      await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.headers,
        },
        body: JSON.stringify(payload),
      });
    } catch (error) {
      console.warn('Failed to export spans:', error);
      // Re-add spans to batch for retry (up to limit)
      if (this.batch.length < this.batchSize * 2) {
        this.batch.unshift(...spans.slice(0, this.batchSize));
      }
    }
  }

  private convertToOTLP(span: SpanData): Record<string, unknown> {
    return {
      traceId: span.traceId,
      spanId: span.spanId,
      parentSpanId: span.parentSpanId,
      name: span.name,
      kind: this.mapSpanKind(span.kind),
      startTimeUnixNano: span.startTime.getTime() * 1e6,
      endTimeUnixNano: span.endTime ? span.endTime.getTime() * 1e6 : undefined,
      attributes: Object.entries(span.attributes).map(([key, value]) => ({
        key,
        value: { stringValue: String(value) },
      })),
      status: {
        code: span.status === SpanStatus.ERROR ? 2 : span.status === SpanStatus.OK ? 1 : 0,
        message: span.statusMessage,
      },
      events: span.events.map(e => ({
        timeUnixNano: e.timestamp.getTime() * 1e6,
        name: e.name,
        attributes: Object.entries(e.attributes).map(([key, value]) => ({
          key,
          value: { stringValue: String(value) },
        })),
      })),
    };
  }

  private mapSpanKind(kind: string): number {
    const kindMap: Record<string, number> = {
      internal: 1,
      server: 2,
      client: 3,
      producer: 4,
      consumer: 5,
    };
    return kindMap[kind] || 0;
  }
}

/**
 * Alert notification handler
 */
export class AlertNotificationHandler {
  private webhookUrl?: string;
  private slackWebhookUrl?: string;
  private pagerDutyKey?: string;

  constructor(config: {
    webhookUrl?: string;
    slackWebhookUrl?: string;
    pagerDutyKey?: string;
  }) {
    this.webhookUrl = config.webhookUrl;
    this.slackWebhookUrl = config.slackWebhookUrl;
    this.pagerDutyKey = config.pagerDutyKey;
  }

  async notify(alert: Alert): Promise<void> {
    const promises: Promise<void>[] = [];

    if (this.webhookUrl) {
      promises.push(this.sendWebhook(alert));
    }

    if (this.slackWebhookUrl) {
      promises.push(this.sendSlack(alert));
    }

    if (this.pagerDutyKey && alert.severity === AlertSeverity.CRITICAL) {
      promises.push(this.sendPagerDuty(alert));
    }

    await Promise.allSettled(promises);
  }

  private async sendWebhook(alert: Alert): Promise<void> {
    if (!this.webhookUrl) return;

    try {
      await fetch(this.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alert),
      });
    } catch (error) {
      console.warn('Failed to send webhook alert:', error);
    }
  }

  private async sendSlack(alert: Alert): Promise<void> {
    if (!this.slackWebhookUrl) return;

    const color = alert.severity === AlertSeverity.CRITICAL ? '#FF0000' :
                  alert.severity === AlertSeverity.WARNING ? '#FFA500' : '#36A64F';

    const emoji = alert.status === 'firing' ? '🚨' : '✅';

    try {
      await fetch(this.slackWebhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attachments: [{
            color,
            title: `${emoji} ${alert.ruleName}`,
            text: alert.status === 'firing'
              ? `Alert triggered: ${alert.metric} = ${alert.value} (threshold: ${alert.threshold})`
              : 'Alert resolved',
            fields: [
              { title: 'Severity', value: alert.severity, short: true },
              { title: 'Status', value: alert.status, short: true },
            ],
            ts: Math.floor(new Date(alert.timestamp).getTime() / 1000),
          }],
        }),
      });
    } catch (error) {
      console.warn('Failed to send Slack alert:', error);
    }
  }

  private async sendPagerDuty(alert: Alert): Promise<void> {
    if (!this.pagerDutyKey) return;

    try {
      await fetch('https://events.pagerduty.com/v2/enqueue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          routing_key: this.pagerDutyKey,
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
      console.warn('Failed to send PagerDuty alert:', error);
    }
  }
}

/**
 * Observability instance containing all monitoring components
 */
export interface ObservabilityInstance {
  metrics: MetricsCollector;
  tracer: Tracer;
  errorTracker: ErrorTracker;
  alertManager: AlertManager;
  alertBridge: AlertNotificationBridge | null;
  swordfishMetrics: SwordfishMetrics;

  // Utility methods
  getMetricsEndpoint: () => string;
  recordHttpRequest: (method: string, route: string, status: number, duration: number) => void;
  recordDbQuery: (operation: string, duration: number) => void;
  recordThreatDetection: (verdict: string, duration: number) => void;
  recordRemediation: (action: string, success: boolean, duration: number) => void;
  recordIntegrationCall: (provider: string, operation: string, success: boolean, duration: number) => void;

  // Shutdown
  shutdown: () => Promise<void>;
}

/**
 * Initialize observability with all components
 */
export function initObservability(config: ObservabilityConfig): ObservabilityInstance {
  const {
    serviceName,
    environment,
    version = '0.0.0',
  } = config;

  // Initialize metrics collector
  const metricsCollector = new MetricsCollector();

  // Create Swordfish-specific metrics
  const swordfishMetrics = createSwordfishMetrics(metricsCollector, config.metrics?.prefix ?? 'swordfish');

  // Initialize tracer
  const tracerConfig = config.tracing ?? {};
  let spanExporter: SpanExporter | undefined;

  if (tracerConfig.enabled && tracerConfig.endpoint) {
    spanExporter = new OTLPSpanExporter({
      endpoint: tracerConfig.endpoint,
      headers: tracerConfig.headers,
    });
  }

  const tracer = new Tracer({
    serviceName,
    environment,
    sampleRate: tracerConfig.sampleRate ?? 1.0,
    exporter: spanExporter,
  });

  // Initialize error tracker
  const errorConfig = config.errorTracking ?? {};
  const errorReporters = [];

  if (errorConfig.enabled) {
    // Console reporter for development
    if (environment === 'development') {
      errorReporters.push(new ConsoleReporter({ includeStack: true }));
    }

    // Webhook reporter for external error tracking (Sentry-compatible)
    if (errorConfig.dsn) {
      const dsnUrl = parseDsn(errorConfig.dsn);
      if (dsnUrl) {
        errorReporters.push(new WebhookReporter({
          url: dsnUrl,
          headers: {
            'X-Sentry-Auth': `Sentry sentry_key=${extractKey(errorConfig.dsn)}`,
          },
        }));
      }
    }
  }

  const errorTracker = new ErrorTracker({
    serviceName,
    environment,
    version,
    sampleRate: errorConfig.sampleRate ?? 1.0,
    reporters: errorReporters,
  });

  // Initialize alert manager
  const alertConfig = config.alerting ?? {};
  const alertHandler = new AlertNotificationHandler({
    webhookUrl: alertConfig.webhookUrl,
    slackWebhookUrl: alertConfig.slackWebhookUrl,
    pagerDutyKey: alertConfig.pagerDutyKey,
  });

  // Initialize alert notification bridge for database-backed notifications
  let alertBridge: AlertNotificationBridge | null = null;
  if (alertConfig.enableDatabaseNotifications) {
    alertBridge = new AlertNotificationBridge(alertConfig.bridgeConfig);
  }

  const alertManager = new AlertManager({
    notify: (alert) => {
      if (alertConfig.enabled) {
        // Send to webhook/Slack/PagerDuty handlers
        alertHandler.notify(alert);

        // Also send to database-backed notification bridge if enabled
        // Note: The bridge requires tenant context, so this is fire-and-forget
        // For tenant-specific alerts, use alertBridge.handleAlert(alert, tenantId) directly
        if (alertBridge) {
          alertBridge.handleAlert(alert).catch((error) => {
            console.warn('[observability] Alert bridge notification failed:', error);
          });
        }
      }
    },
  });

  // Register predefined alert rules
  if (alertConfig.enabled) {
    for (const rule of alertManager.getPredefinedRules()) {
      alertManager.registerRule(rule);
    }
  }

  // Return observability instance
  return {
    metrics: metricsCollector,
    tracer,
    errorTracker,
    alertManager,
    alertBridge,
    swordfishMetrics,

    getMetricsEndpoint: () => metricsCollector.getRegistry().toPrometheusFormat(),

    recordHttpRequest: (method, route, status, duration) => {
      swordfishMetrics.httpRequestsTotal.labels({ method, route, status: String(status) }).inc();
      swordfishMetrics.httpRequestDuration.labels({ method, route }).observe(duration);
    },

    recordDbQuery: (operation, duration) => {
      swordfishMetrics.dbQueriesTotal.labels({ operation }).inc();
      swordfishMetrics.dbQueryDuration.labels({ operation }).observe(duration);
    },

    recordThreatDetection: (verdict, duration) => {
      swordfishMetrics.threatsDetected.labels({ verdict }).inc();
      swordfishMetrics.threatDetectionDuration.observe(duration);
      swordfishMetrics.verdictDistribution.labels({ verdict }).inc();
    },

    recordRemediation: (action, success, duration) => {
      swordfishMetrics.remediationActions.labels({ action, status: success ? 'success' : 'failure' }).inc();
      swordfishMetrics.remediationDuration.labels({ action }).observe(duration);
      if (!success) {
        swordfishMetrics.remediationFailures.labels({ action }).inc();
      }
    },

    recordIntegrationCall: (provider, operation, success, duration) => {
      swordfishMetrics.integrationCalls.labels({ provider, operation }).inc();
      swordfishMetrics.integrationLatency.labels({ provider, operation }).observe(duration);
      if (!success) {
        swordfishMetrics.integrationErrors.labels({ provider, operation }).inc();
      }
    },

    shutdown: async () => {
      await errorTracker.shutdown();
      if (spanExporter && 'flush' in spanExporter) {
        await (spanExporter as OTLPSpanExporter).flush();
      }
    },
  };
}

/**
 * Create Swordfish-specific metrics
 */
function createSwordfishMetrics(collector: MetricsCollector, prefix: string): SwordfishMetrics {
  return {
    // Email processing
    emailsProcessed: collector.counter(
      `${prefix}_emails_processed_total`,
      'Total number of emails processed',
      ['integration_type', 'tenant_id']
    ),
    emailProcessingDuration: collector.histogram(
      `${prefix}_email_processing_duration_seconds`,
      'Email processing duration in seconds',
      ['integration_type'],
      { buckets: [0.1, 0.5, 1, 2, 5, 10, 30] }
    ),
    emailsInQueue: collector.gauge(
      `${prefix}_emails_in_queue`,
      'Number of emails currently in processing queue',
      ['integration_type']
    ),

    // Threat detection
    threatsDetected: collector.counter(
      `${prefix}_threats_detected_total`,
      'Total number of threats detected',
      ['verdict', 'tenant_id']
    ),
    threatDetectionDuration: collector.histogram(
      `${prefix}_threat_detection_duration_seconds`,
      'Threat detection duration in seconds',
      [],
      { buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5] }
    ),
    verdictDistribution: collector.counter(
      `${prefix}_verdict_distribution_total`,
      'Distribution of detection verdicts',
      ['verdict']
    ),

    // Remediation
    remediationActions: collector.counter(
      `${prefix}_remediation_actions_total`,
      'Total remediation actions taken',
      ['action', 'status', 'integration_type']
    ),
    remediationDuration: collector.histogram(
      `${prefix}_remediation_duration_seconds`,
      'Remediation action duration in seconds',
      ['action'],
      { buckets: [0.1, 0.5, 1, 2, 5, 10] }
    ),
    remediationFailures: collector.counter(
      `${prefix}_remediation_failures_total`,
      'Total remediation failures',
      ['action', 'reason']
    ),

    // API metrics
    httpRequestsTotal: collector.counter(
      `${prefix}_http_requests_total`,
      'Total HTTP requests',
      ['method', 'route', 'status']
    ),
    httpRequestDuration: collector.histogram(
      `${prefix}_http_request_duration_seconds`,
      'HTTP request duration in seconds',
      ['method', 'route'],
      { buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10] }
    ),
    httpRequestsInFlight: collector.gauge(
      `${prefix}_http_requests_in_flight`,
      'Number of HTTP requests currently being processed',
      ['method']
    ),

    // Integration metrics
    integrationCalls: collector.counter(
      `${prefix}_integration_calls_total`,
      'Total external API calls',
      ['provider', 'operation']
    ),
    integrationLatency: collector.histogram(
      `${prefix}_integration_latency_seconds`,
      'External API call latency in seconds',
      ['provider', 'operation'],
      { buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10] }
    ),
    integrationErrors: collector.counter(
      `${prefix}_integration_errors_total`,
      'Total external API call errors',
      ['provider', 'operation', 'error_type']
    ),

    // Database metrics
    dbQueriesTotal: collector.counter(
      `${prefix}_db_queries_total`,
      'Total database queries',
      ['operation', 'table']
    ),
    dbQueryDuration: collector.histogram(
      `${prefix}_db_query_duration_seconds`,
      'Database query duration in seconds',
      ['operation'],
      { buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1] }
    ),
    dbConnectionPoolSize: collector.gauge(
      `${prefix}_db_connection_pool_size`,
      'Database connection pool size',
      ['state']
    ),
  };
}

/**
 * Parse Sentry-style DSN to URL
 */
function parseDsn(dsn: string): string | null {
  try {
    const url = new URL(dsn);
    const projectId = url.pathname.replace(/\//g, '');
    return `${url.protocol}//${url.host}/api/${projectId}/store/`;
  } catch {
    return null;
  }
}

/**
 * Extract key from DSN
 */
function extractKey(dsn: string): string {
  try {
    const url = new URL(dsn);
    return url.username;
  } catch {
    return '';
  }
}

/**
 * Default observability instance (lazy-initialized)
 */
let defaultObservability: ObservabilityInstance | null = null;

/**
 * Get or initialize default observability instance
 */
export function getObservability(config?: ObservabilityConfig): ObservabilityInstance {
  if (!defaultObservability && config) {
    defaultObservability = initObservability(config);
  }
  if (!defaultObservability) {
    throw new Error('Observability not initialized. Call initObservability first.');
  }
  return defaultObservability;
}

/**
 * Initialize default observability from environment variables
 */
export function initFromEnv(): ObservabilityInstance {
  const config: ObservabilityConfig = {
    serviceName: process.env.SERVICE_NAME ?? 'swordfish',
    environment: process.env.NODE_ENV ?? 'development',
    version: process.env.APP_VERSION ?? '0.0.0',

    metrics: {
      enabled: process.env.METRICS_ENABLED !== 'false',
      prefix: process.env.METRICS_PREFIX ?? 'swordfish',
    },

    tracing: {
      enabled: process.env.TRACING_ENABLED === 'true',
      sampleRate: parseFloat(process.env.TRACING_SAMPLE_RATE ?? '1.0'),
      endpoint: process.env.OTLP_ENDPOINT,
      headers: process.env.OTLP_HEADERS ? JSON.parse(process.env.OTLP_HEADERS) : undefined,
    },

    errorTracking: {
      enabled: process.env.ERROR_TRACKING_ENABLED === 'true',
      sampleRate: parseFloat(process.env.ERROR_SAMPLE_RATE ?? '1.0'),
      dsn: process.env.SENTRY_DSN,
    },

    alerting: {
      enabled: process.env.ALERTING_ENABLED === 'true',
      webhookUrl: process.env.ALERT_WEBHOOK_URL,
      slackWebhookUrl: process.env.SLACK_WEBHOOK_URL,
      pagerDutyKey: process.env.PAGERDUTY_ROUTING_KEY,
      enableDatabaseNotifications: process.env.ALERT_DB_NOTIFICATIONS_ENABLED === 'true',
    },
  };

  return initObservability(config);
}
