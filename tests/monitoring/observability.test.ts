/**
 * Observability Module Tests
 * Tests for unified monitoring, tracing, and error tracking setup
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  initObservability,
  initFromEnv,
  ObservabilityConfig,
  OTLPSpanExporter,
  AlertNotificationHandler,
} from '../../lib/monitoring/observability';
import { AlertSeverity, Alert } from '../../lib/monitoring/alerts';
import { SpanStatus } from '../../lib/monitoring/tracing';

describe('Observability Module', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch = vi.fn().mockResolvedValue({ ok: true });
    global.fetch = mockFetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('initObservability', () => {
    it('should initialize with basic configuration', () => {
      const config: ObservabilityConfig = {
        serviceName: 'test-service',
        environment: 'test',
      };

      const obs = initObservability(config);

      expect(obs).toBeDefined();
      expect(obs.metrics).toBeDefined();
      expect(obs.tracer).toBeDefined();
      expect(obs.errorTracker).toBeDefined();
      expect(obs.alertManager).toBeDefined();
      expect(obs.swordfishMetrics).toBeDefined();
    });

    it('should create all Swordfish-specific metrics', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
      });

      const metrics = obs.swordfishMetrics;

      // Email processing
      expect(metrics.emailsProcessed).toBeDefined();
      expect(metrics.emailProcessingDuration).toBeDefined();
      expect(metrics.emailsInQueue).toBeDefined();

      // Threat detection
      expect(metrics.threatsDetected).toBeDefined();
      expect(metrics.threatDetectionDuration).toBeDefined();
      expect(metrics.verdictDistribution).toBeDefined();

      // Remediation
      expect(metrics.remediationActions).toBeDefined();
      expect(metrics.remediationDuration).toBeDefined();
      expect(metrics.remediationFailures).toBeDefined();

      // API
      expect(metrics.httpRequestsTotal).toBeDefined();
      expect(metrics.httpRequestDuration).toBeDefined();
      expect(metrics.httpRequestsInFlight).toBeDefined();

      // Integration
      expect(metrics.integrationCalls).toBeDefined();
      expect(metrics.integrationLatency).toBeDefined();
      expect(metrics.integrationErrors).toBeDefined();

      // Database
      expect(metrics.dbQueriesTotal).toBeDefined();
      expect(metrics.dbQueryDuration).toBeDefined();
      expect(metrics.dbConnectionPoolSize).toBeDefined();
    });

    it('should configure tracer with sample rate', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
        tracing: {
          enabled: true,
          sampleRate: 0.5,
        },
      });

      const config = obs.tracer.getConfig();
      expect(config.sampleRate).toBe(0.5);
    });

    it('should configure error tracker with reporters', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'development',
        errorTracking: {
          enabled: true,
          sampleRate: 1.0,
        },
      });

      const config = obs.errorTracker.getConfig();
      expect(config.sampleRate).toBe(1.0);
      expect(config.serviceName).toBe('test');
    });

    it('should register predefined alert rules when alerting is enabled', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
        alerting: {
          enabled: true,
        },
      });

      const rules = obs.alertManager.getRules();
      expect(rules.length).toBeGreaterThan(0);
      expect(rules.some(r => r.id === 'high-threat-rate')).toBe(true);
    });

    it('should provide Prometheus metrics endpoint', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
      });

      const metricsOutput = obs.getMetricsEndpoint();

      expect(metricsOutput).toContain('# HELP');
      expect(metricsOutput).toContain('# TYPE');
    });
  });

  describe('Utility Methods', () => {
    it('should record HTTP requests', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
      });

      obs.recordHttpRequest('GET', '/api/threats', 200, 0.1);
      obs.recordHttpRequest('POST', '/api/threats', 201, 0.25);

      const metricsOutput = obs.getMetricsEndpoint();
      expect(metricsOutput).toContain('swordfish_http_requests_total');
    });

    it('should record database queries', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
      });

      obs.recordDbQuery('SELECT', 0.005);
      obs.recordDbQuery('INSERT', 0.01);

      const metricsOutput = obs.getMetricsEndpoint();
      expect(metricsOutput).toContain('swordfish_db_queries_total');
    });

    it('should record threat detection', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
      });

      obs.recordThreatDetection('quarantine', 0.5);
      obs.recordThreatDetection('clean', 0.2);

      const metricsOutput = obs.getMetricsEndpoint();
      expect(metricsOutput).toContain('swordfish_threats_detected_total');
    });

    it('should record remediation actions', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
      });

      obs.recordRemediation('quarantine', true, 1.0);
      obs.recordRemediation('delete', false, 2.0);

      const metricsOutput = obs.getMetricsEndpoint();
      expect(metricsOutput).toContain('swordfish_remediation_actions_total');
    });

    it('should record integration calls', () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
      });

      obs.recordIntegrationCall('virustotal', 'scan', true, 0.5);
      obs.recordIntegrationCall('gmail', 'modify', false, 1.0);

      const metricsOutput = obs.getMetricsEndpoint();
      expect(metricsOutput).toContain('swordfish_integration_calls_total');
    });
  });

  describe('OTLPSpanExporter', () => {
    it('should batch spans before export', async () => {
      const exporter = new OTLPSpanExporter({
        endpoint: 'https://otlp.example.com/v1/traces',
        batchSize: 5,
      });

      // Add 4 spans - shouldn't trigger export yet
      for (let i = 0; i < 4; i++) {
        exporter.export({
          name: `span-${i}`,
          traceId: 'trace-123',
          spanId: `span-${i}`,
          kind: 'internal',
          startTime: new Date(),
          status: SpanStatus.OK,
          attributes: {},
          events: [],
          sampled: true,
        });
      }

      expect(mockFetch).not.toHaveBeenCalled();

      // 5th span triggers batch export
      exporter.export({
        name: 'span-5',
        traceId: 'trace-123',
        spanId: 'span-5',
        kind: 'internal',
        startTime: new Date(),
        status: SpanStatus.OK,
        attributes: {},
        events: [],
        sampled: true,
      });

      // Allow async operation to complete
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(mockFetch).toHaveBeenCalledWith(
        'https://otlp.example.com/v1/traces',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      );
    });

    it('should send custom headers', async () => {
      const exporter = new OTLPSpanExporter({
        endpoint: 'https://otlp.example.com/v1/traces',
        headers: {
          'X-API-Key': 'test-key',
        },
        batchSize: 1,
      });

      exporter.export({
        name: 'test-span',
        traceId: 'trace-123',
        spanId: 'span-1',
        kind: 'server',
        startTime: new Date(),
        status: SpanStatus.OK,
        attributes: {},
        events: [],
        sampled: true,
      });

      await new Promise(resolve => setTimeout(resolve, 10));

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-API-Key': 'test-key',
          }),
        })
      );
    });

    it('should handle export errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const exporter = new OTLPSpanExporter({
        endpoint: 'https://otlp.example.com/v1/traces',
        batchSize: 1,
      });

      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      exporter.export({
        name: 'test-span',
        traceId: 'trace-123',
        spanId: 'span-1',
        kind: 'internal',
        startTime: new Date(),
        status: SpanStatus.OK,
        attributes: {},
        events: [],
        sampled: true,
      });

      await new Promise(resolve => setTimeout(resolve, 50));

      expect(consoleSpy).toHaveBeenCalledWith(
        'Failed to export spans:',
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });
  });

  describe('AlertNotificationHandler', () => {
    it('should send webhook alerts', async () => {
      const handler = new AlertNotificationHandler({
        webhookUrl: 'https://alerts.example.com/webhook',
      });

      const alert: Alert = {
        ruleId: 'test-rule',
        ruleName: 'Test Alert',
        severity: AlertSeverity.WARNING,
        status: 'firing',
        timestamp: new Date().toISOString(),
        value: 100,
        threshold: 50,
        metric: 'test_metric',
      };

      await handler.notify(alert);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://alerts.example.com/webhook',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('test-rule'),
        })
      );
    });

    it('should send Slack alerts with correct formatting', async () => {
      const handler = new AlertNotificationHandler({
        slackWebhookUrl: 'https://hooks.slack.com/services/xxx',
      });

      const alert: Alert = {
        ruleId: 'critical-alert',
        ruleName: 'Critical Issue',
        severity: AlertSeverity.CRITICAL,
        status: 'firing',
        timestamp: new Date().toISOString(),
      };

      await handler.notify(alert);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://hooks.slack.com/services/xxx',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('Critical Issue'),
        })
      );

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.attachments[0].color).toBe('#FF0000'); // Red for critical
    });

    it('should send PagerDuty alerts for critical severity', async () => {
      const handler = new AlertNotificationHandler({
        pagerDutyKey: 'pd-routing-key',
      });

      const alert: Alert = {
        ruleId: 'critical-alert',
        ruleName: 'Critical Issue',
        severity: AlertSeverity.CRITICAL,
        status: 'firing',
        timestamp: new Date().toISOString(),
      };

      await handler.notify(alert);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://events.pagerduty.com/v2/enqueue',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('pd-routing-key'),
        })
      );
    });

    it('should not send PagerDuty alerts for non-critical severity', async () => {
      const handler = new AlertNotificationHandler({
        pagerDutyKey: 'pd-routing-key',
      });

      const alert: Alert = {
        ruleId: 'warning-alert',
        ruleName: 'Warning Issue',
        severity: AlertSeverity.WARNING,
        status: 'firing',
        timestamp: new Date().toISOString(),
      };

      await handler.notify(alert);

      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('initFromEnv', () => {
    it('should initialize from environment variables', () => {
      const originalEnv = process.env;

      process.env = {
        ...originalEnv,
        SERVICE_NAME: 'env-test-service',
        NODE_ENV: 'test',
        METRICS_ENABLED: 'true',
        METRICS_PREFIX: 'custom_prefix',
      };

      const obs = initFromEnv();

      expect(obs).toBeDefined();
      expect(obs.tracer.getConfig().serviceName).toBe('env-test-service');

      process.env = originalEnv;
    });

    it('should use defaults when env vars not set', () => {
      const originalEnv = process.env;

      // Remove relevant env vars
      process.env = { ...originalEnv };
      delete process.env.SERVICE_NAME;
      delete process.env.METRICS_PREFIX;

      const obs = initFromEnv();

      expect(obs).toBeDefined();
      expect(obs.tracer.getConfig().serviceName).toBe('swordfish');

      process.env = originalEnv;
    });
  });

  describe('Shutdown', () => {
    it('should gracefully shutdown all components', async () => {
      const obs = initObservability({
        serviceName: 'test',
        environment: 'test',
        tracing: {
          enabled: true,
          endpoint: 'https://otlp.example.com/v1/traces',
        },
      });

      // Create a span to ensure there's something to flush
      const span = obs.tracer.startSpan('test-span');
      span.end();

      await obs.shutdown();

      // Shutdown should complete without error
      expect(true).toBe(true);
    });
  });
});

console.log('Test suite complete.');
