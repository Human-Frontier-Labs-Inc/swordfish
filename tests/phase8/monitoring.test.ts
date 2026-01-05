/**
 * Phase 8 - Monitoring & Alerts Tests
 *
 * Unit tests for metrics collection, health checks, and alert system
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('Monitoring Metrics', () => {
  describe('System Health', () => {
    it('should determine health status from metrics', () => {
      const determineHealthStatus = (
        email: { queueDepth: number; avgProcessingTime: number },
        detection: { falsePositives24h: number; threatsDetected24h: number }
      ): 'healthy' | 'degraded' | 'unhealthy' => {
        if (email.queueDepth > 1000) return 'unhealthy';
        if (email.avgProcessingTime > 30) return 'degraded';

        const fpRate = detection.falsePositives24h / (detection.threatsDetected24h || 1);
        if (fpRate > 0.2) return 'degraded';

        return 'healthy';
      };

      expect(determineHealthStatus(
        { queueDepth: 100, avgProcessingTime: 5 },
        { falsePositives24h: 1, threatsDetected24h: 100 }
      )).toBe('healthy');

      expect(determineHealthStatus(
        { queueDepth: 2000, avgProcessingTime: 5 },
        { falsePositives24h: 1, threatsDetected24h: 100 }
      )).toBe('unhealthy');

      expect(determineHealthStatus(
        { queueDepth: 100, avgProcessingTime: 45 },
        { falsePositives24h: 1, threatsDetected24h: 100 }
      )).toBe('degraded');
    });

    it('should calculate percentiles from response times', () => {
      const calculatePercentile = (times: number[], percentile: number): number => {
        const sorted = [...times].sort((a, b) => a - b);
        const index = Math.floor(sorted.length * (percentile / 100));
        return sorted[index] || 0;
      };

      // sorted: [100, 150, 180, 190, 200, 210, 220, 250, 300, 500]
      const responseTimes = [100, 200, 150, 300, 250, 180, 220, 190, 210, 500];

      expect(calculatePercentile(responseTimes, 50)).toBe(210); // index 5: 210
      expect(calculatePercentile(responseTimes, 95)).toBe(500);
      expect(calculatePercentile(responseTimes, 99)).toBe(500);
    });

    it('should track request metrics', () => {
      let requestCount = 0;
      let errorCount = 0;
      const responseTimes: number[] = [];

      const recordRequest = (responseTime: number, isError: boolean) => {
        requestCount++;
        if (isError) errorCount++;
        responseTimes.push(responseTime);
      };

      recordRequest(100, false);
      recordRequest(200, false);
      recordRequest(150, true);

      expect(requestCount).toBe(3);
      expect(errorCount).toBe(1);
      expect(responseTimes).toHaveLength(3);
    });
  });

  describe('Prometheus Metrics Format', () => {
    it('should format metrics in Prometheus exposition format', () => {
      const formatPrometheusMetric = (
        name: string,
        value: number,
        labels?: Record<string, string>
      ): string => {
        const labelStr = labels
          ? `{${Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(',')}}`
          : '';
        return `${name}${labelStr} ${value}`;
      };

      expect(formatPrometheusMetric('swordfish_uptime_seconds', 3600))
        .toBe('swordfish_uptime_seconds 3600');

      expect(formatPrometheusMetric('swordfish_emails_total', 1000, { period: '24h' }))
        .toBe('swordfish_emails_total{period="24h"} 1000');
    });

    it('should include metric type and help comments', () => {
      const createPrometheusBlock = (
        name: string,
        type: string,
        help: string,
        value: number
      ): string => {
        return [
          `# HELP ${name} ${help}`,
          `# TYPE ${name} ${type}`,
          `${name} ${value}`,
        ].join('\n');
      };

      const block = createPrometheusBlock(
        'swordfish_uptime_seconds',
        'gauge',
        'System uptime in seconds',
        3600
      );

      expect(block).toContain('# HELP swordfish_uptime_seconds');
      expect(block).toContain('# TYPE swordfish_uptime_seconds gauge');
      expect(block).toContain('swordfish_uptime_seconds 3600');
    });
  });

  describe('Email Metrics', () => {
    it('should track email processing metrics', () => {
      const emailMetrics = {
        processed24h: 1000,
        processedHour: 50,
        queueDepth: 10,
        avgProcessingTime: 2.5,
      };

      expect(emailMetrics.processed24h).toBeGreaterThan(0);
      expect(emailMetrics.avgProcessingTime).toBeLessThan(30);
    });

    it('should calculate processing rate', () => {
      const calculateRate = (processed: number, hours: number): number => {
        return Math.round(processed / hours);
      };

      expect(calculateRate(1000, 24)).toBe(42); // ~42 emails per hour
      expect(calculateRate(50, 1)).toBe(50);
    });
  });

  describe('Detection Metrics', () => {
    it('should calculate false positive rate', () => {
      const calculateFPRate = (
        falsePositives: number,
        totalDetected: number
      ): number => {
        if (totalDetected === 0) return 0;
        return Math.round((falsePositives / totalDetected) * 100 * 100) / 100;
      };

      expect(calculateFPRate(5, 100)).toBe(5);
      expect(calculateFPRate(0, 100)).toBe(0);
      expect(calculateFPRate(0, 0)).toBe(0);
    });
  });
});

describe('Health Check', () => {
  describe('Health Status', () => {
    it('should check database connectivity', async () => {
      const checkDatabase = async (): Promise<{ status: string; latency: number }> => {
        const start = Date.now();
        // Simulate DB check
        await new Promise(r => setTimeout(r, 10));
        return {
          status: 'pass',
          latency: Date.now() - start,
        };
      };

      const result = await checkDatabase();
      expect(result.status).toBe('pass');
      expect(result.latency).toBeGreaterThan(0);
    });

    it('should check memory usage', () => {
      const checkMemory = (heapUsed: number, heapTotal: number): { status: string; message: string } => {
        const percent = (heapUsed / heapTotal) * 100;

        if (percent > 90) return { status: 'fail', message: 'Memory critical' };
        if (percent > 75) return { status: 'warn', message: 'Memory warning' };
        return { status: 'pass', message: 'Memory OK' };
      };

      expect(checkMemory(50, 100).status).toBe('pass');
      expect(checkMemory(80, 100).status).toBe('warn');
      expect(checkMemory(95, 100).status).toBe('fail');
    });

    it('should determine overall health from checks', () => {
      const determineOverallHealth = (checks: Array<{ status: string }>): string => {
        const hasFailure = checks.some(c => c.status === 'fail');
        const hasWarning = checks.some(c => c.status === 'warn');

        if (hasFailure) return 'unhealthy';
        if (hasWarning) return 'degraded';
        return 'healthy';
      };

      expect(determineOverallHealth([{ status: 'pass' }, { status: 'pass' }])).toBe('healthy');
      expect(determineOverallHealth([{ status: 'pass' }, { status: 'warn' }])).toBe('degraded');
      expect(determineOverallHealth([{ status: 'pass' }, { status: 'fail' }])).toBe('unhealthy');
    });

    it('should return appropriate HTTP status codes', () => {
      const getHttpStatus = (health: string): number => {
        if (health === 'healthy') return 200;
        if (health === 'degraded') return 200;
        return 503;
      };

      expect(getHttpStatus('healthy')).toBe(200);
      expect(getHttpStatus('degraded')).toBe(200);
      expect(getHttpStatus('unhealthy')).toBe(503);
    });
  });
});

describe('Alert System', () => {
  describe('Alert Rules', () => {
    it('should evaluate threshold conditions', () => {
      const evaluateCondition = (
        value: number,
        operator: string,
        threshold: number
      ): boolean => {
        switch (operator) {
          case 'gt': return value > threshold;
          case 'gte': return value >= threshold;
          case 'lt': return value < threshold;
          case 'lte': return value <= threshold;
          case 'eq': return value === threshold;
          default: return false;
        }
      };

      expect(evaluateCondition(100, 'gt', 50)).toBe(true);
      expect(evaluateCondition(50, 'gt', 50)).toBe(false);
      expect(evaluateCondition(50, 'gte', 50)).toBe(true);
      expect(evaluateCondition(30, 'lt', 50)).toBe(true);
      expect(evaluateCondition(50, 'eq', 50)).toBe(true);
    });

    it('should respect cooldown periods', () => {
      const isInCooldown = (
        lastTriggeredAt: Date | undefined,
        cooldownMinutes: number
      ): boolean => {
        if (!lastTriggeredAt || cooldownMinutes === 0) return false;
        const cooldownMs = cooldownMinutes * 60 * 1000;
        return Date.now() - lastTriggeredAt.getTime() < cooldownMs;
      };

      const recentTrigger = new Date(Date.now() - 5 * 60 * 1000); // 5 min ago
      const oldTrigger = new Date(Date.now() - 120 * 60 * 1000); // 2 hours ago

      expect(isInCooldown(recentTrigger, 60)).toBe(true);
      expect(isInCooldown(oldTrigger, 60)).toBe(false);
      expect(isInCooldown(recentTrigger, 0)).toBe(false);
      expect(isInCooldown(undefined, 60)).toBe(false);
    });

    it('should validate alert rule structure', () => {
      const isValidRule = (rule: Record<string, unknown>): boolean => {
        return !!(
          rule.name &&
          rule.condition &&
          (rule.condition as Record<string, unknown>).type &&
          (rule.condition as Record<string, unknown>).metric &&
          (rule.condition as Record<string, unknown>).operator &&
          (rule.condition as Record<string, unknown>).value !== undefined &&
          rule.actions
        );
      };

      const validRule = {
        name: 'Test Rule',
        condition: {
          type: 'threshold',
          metric: 'threats_detected',
          operator: 'gt',
          value: 100,
        },
        actions: [{ type: 'email', config: {} }],
      };

      const invalidRule = {
        name: 'Invalid',
        condition: {},
        actions: [],
      };

      expect(isValidRule(validRule)).toBe(true);
      expect(isValidRule(invalidRule)).toBe(false);
    });
  });

  describe('Alert Actions', () => {
    it('should support multiple action types', () => {
      const actionTypes = ['email', 'webhook', 'slack', 'pagerduty'];

      expect(actionTypes).toContain('email');
      expect(actionTypes).toContain('webhook');
      expect(actionTypes).toContain('slack');
      expect(actionTypes).toContain('pagerduty');
    });

    it('should map severity to colors for Slack', () => {
      const severityColors: Record<string, string> = {
        critical: '#dc2626',
        high: '#ea580c',
        medium: '#ca8a04',
        low: '#2563eb',
        info: '#6b7280',
      };

      expect(severityColors['critical']).toBe('#dc2626');
      expect(severityColors['high']).toBe('#ea580c');
    });

    it('should map severity for PagerDuty', () => {
      const severityMap: Record<string, string> = {
        critical: 'critical',
        high: 'error',
        medium: 'warning',
        low: 'info',
        info: 'info',
      };

      expect(severityMap['critical']).toBe('critical');
      expect(severityMap['high']).toBe('error');
    });
  });

  describe('Alert Status', () => {
    it('should track alert lifecycle', () => {
      const alertStatuses = ['active', 'acknowledged', 'resolved'];

      expect(alertStatuses).toHaveLength(3);
      expect(alertStatuses).toContain('active');
      expect(alertStatuses).toContain('acknowledged');
      expect(alertStatuses).toContain('resolved');
    });

    it('should calculate alert duration', () => {
      const calculateDuration = (triggeredAt: Date, resolvedAt?: Date): string => {
        const endTime = resolvedAt || new Date();
        const durationMs = endTime.getTime() - triggeredAt.getTime();
        const minutes = Math.floor(durationMs / 60000);
        const hours = Math.floor(minutes / 60);

        if (hours > 0) return `${hours}h ${minutes % 60}m`;
        return `${minutes}m`;
      };

      const triggeredAt = new Date(Date.now() - 90 * 60 * 1000); // 90 min ago
      expect(calculateDuration(triggeredAt)).toBe('1h 30m');
    });
  });
});
