/**
 * Metrics Collection Tests
 * TDD: Application metrics for monitoring and alerting
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  MetricsCollector,
  createMetricsCollector,
  Counter,
  Gauge,
  Histogram,
  MetricType,
  MetricsRegistry,
} from '@/lib/monitoring/metrics';

describe('Metrics Collection', () => {
  let collector: MetricsCollector;

  beforeEach(() => {
    collector = createMetricsCollector();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Counter', () => {
    it('should create a counter metric', () => {
      const counter = collector.counter('http_requests_total', 'Total HTTP requests');

      expect(counter).toBeDefined();
      expect(counter.type).toBe(MetricType.COUNTER);
    });

    it('should increment counter', () => {
      const counter = collector.counter('http_requests_total', 'Total HTTP requests');

      counter.inc();
      counter.inc();
      counter.inc();

      expect(counter.get()).toBe(3);
    });

    it('should increment by specific value', () => {
      const counter = collector.counter('bytes_sent_total', 'Total bytes sent');

      counter.inc(1024);
      counter.inc(2048);

      expect(counter.get()).toBe(3072);
    });

    it('should support labels', () => {
      const counter = collector.counter('http_requests_total', 'Total HTTP requests', [
        'method',
        'status',
      ]);

      counter.labels({ method: 'GET', status: '200' }).inc();
      counter.labels({ method: 'GET', status: '200' }).inc();
      counter.labels({ method: 'POST', status: '201' }).inc();

      expect(counter.labels({ method: 'GET', status: '200' }).get()).toBe(2);
      expect(counter.labels({ method: 'POST', status: '201' }).get()).toBe(1);
    });

    it('should not allow negative increments', () => {
      const counter = collector.counter('test_counter', 'Test');

      expect(() => counter.inc(-1)).toThrow();
    });
  });

  describe('Gauge', () => {
    it('should create a gauge metric', () => {
      const gauge = collector.gauge('active_connections', 'Active connections');

      expect(gauge).toBeDefined();
      expect(gauge.type).toBe(MetricType.GAUGE);
    });

    it('should set gauge value', () => {
      const gauge = collector.gauge('active_connections', 'Active connections');

      gauge.set(42);

      expect(gauge.get()).toBe(42);
    });

    it('should increment gauge', () => {
      const gauge = collector.gauge('active_connections', 'Active connections');

      gauge.set(10);
      gauge.inc();
      gauge.inc(5);

      expect(gauge.get()).toBe(16);
    });

    it('should decrement gauge', () => {
      const gauge = collector.gauge('active_connections', 'Active connections');

      gauge.set(10);
      gauge.dec();
      gauge.dec(3);

      expect(gauge.get()).toBe(6);
    });

    it('should support labels', () => {
      const gauge = collector.gauge('queue_size', 'Queue size', ['queue_name']);

      gauge.labels({ queue_name: 'emails' }).set(100);
      gauge.labels({ queue_name: 'threats' }).set(50);

      expect(gauge.labels({ queue_name: 'emails' }).get()).toBe(100);
      expect(gauge.labels({ queue_name: 'threats' }).get()).toBe(50);
    });
  });

  describe('Histogram', () => {
    it('should create a histogram metric', () => {
      const histogram = collector.histogram('http_request_duration_seconds', 'Request duration');

      expect(histogram).toBeDefined();
      expect(histogram.type).toBe(MetricType.HISTOGRAM);
    });

    it('should observe values', () => {
      const histogram = collector.histogram('http_request_duration_seconds', 'Request duration');

      histogram.observe(0.1);
      histogram.observe(0.2);
      histogram.observe(0.5);

      const stats = histogram.getStats();
      expect(stats.count).toBe(3);
      expect(stats.sum).toBeCloseTo(0.8);
    });

    it('should calculate percentiles', () => {
      const histogram = collector.histogram('http_request_duration_seconds', 'Request duration');

      // Add 100 observations from 0.01 to 1.0
      for (let i = 1; i <= 100; i++) {
        histogram.observe(i / 100);
      }

      const p50 = histogram.percentile(50);
      const p95 = histogram.percentile(95);
      const p99 = histogram.percentile(99);

      expect(p50).toBeCloseTo(0.5, 1);
      expect(p95).toBeCloseTo(0.95, 1);
      expect(p99).toBeCloseTo(0.99, 1);
    });

    it('should support labels', () => {
      const histogram = collector.histogram(
        'http_request_duration_seconds',
        'Request duration',
        ['method']
      );

      histogram.labels({ method: 'GET' }).observe(0.1);
      histogram.labels({ method: 'POST' }).observe(0.5);

      expect(histogram.labels({ method: 'GET' }).getStats().count).toBe(1);
      expect(histogram.labels({ method: 'POST' }).getStats().count).toBe(1);
    });

    it('should support custom buckets', () => {
      const histogram = collector.histogram(
        'http_request_duration_seconds',
        'Request duration',
        [],
        { buckets: [0.01, 0.05, 0.1, 0.5, 1, 5] }
      );

      histogram.observe(0.03);
      histogram.observe(0.08);
      histogram.observe(0.3);

      const buckets = histogram.getBuckets();
      expect(buckets).toBeDefined();
    });

    it('should provide timing helper', async () => {
      const histogram = collector.histogram('operation_duration_seconds', 'Operation duration');

      const end = histogram.startTimer();
      await new Promise((r) => setTimeout(r, 50));
      const duration = end();

      expect(duration).toBeGreaterThanOrEqual(0.05);
      expect(histogram.getStats().count).toBe(1);
    });
  });

  describe('MetricsRegistry', () => {
    it('should register metrics', () => {
      collector.counter('test_counter', 'Test counter');
      collector.gauge('test_gauge', 'Test gauge');

      const registry = collector.getRegistry();
      expect(registry.getMetricNames()).toContain('test_counter');
      expect(registry.getMetricNames()).toContain('test_gauge');
    });

    it('should prevent duplicate metric names', () => {
      collector.counter('duplicate_name', 'First');

      expect(() => collector.counter('duplicate_name', 'Second')).toThrow();
    });

    it('should export metrics in Prometheus format', () => {
      const counter = collector.counter('http_requests_total', 'Total HTTP requests');
      counter.inc(100);

      const output = collector.getRegistry().toPrometheusFormat();

      expect(output).toContain('# HELP http_requests_total Total HTTP requests');
      expect(output).toContain('# TYPE http_requests_total counter');
      expect(output).toContain('http_requests_total 100');
    });

    it('should export metrics as JSON', () => {
      const counter = collector.counter('http_requests_total', 'Total HTTP requests');
      counter.inc(100);

      const json = collector.getRegistry().toJSON();

      expect(json).toHaveProperty('http_requests_total');
      expect(json.http_requests_total.value).toBe(100);
    });

    it('should reset all metrics', () => {
      const counter = collector.counter('test_counter', 'Test');
      const gauge = collector.gauge('test_gauge', 'Test');

      counter.inc(10);
      gauge.set(50);

      collector.getRegistry().reset();

      expect(counter.get()).toBe(0);
      expect(gauge.get()).toBe(0);
    });
  });

  describe('Default metrics', () => {
    it('should collect process metrics', () => {
      collector.collectDefaultMetrics();

      const registry = collector.getRegistry();
      const names = registry.getMetricNames();

      expect(names).toContain('process_cpu_seconds_total');
      expect(names).toContain('process_memory_bytes');
    });

    it('should collect nodejs metrics', () => {
      collector.collectDefaultMetrics();

      const registry = collector.getRegistry();
      const names = registry.getMetricNames();

      expect(names).toContain('nodejs_heap_size_bytes');
      expect(names).toContain('nodejs_event_loop_lag_seconds');
    });
  });

  describe('Metric middleware', () => {
    it('should track request metrics', () => {
      const requestCounter = collector.counter('http_requests_total', 'Total requests', [
        'method',
        'path',
        'status',
      ]);
      const requestDuration = collector.histogram(
        'http_request_duration_seconds',
        'Request duration',
        ['method', 'path']
      );

      // Simulate request tracking
      requestCounter.labels({ method: 'GET', path: '/api/threats', status: '200' }).inc();
      requestDuration.labels({ method: 'GET', path: '/api/threats' }).observe(0.15);

      expect(requestCounter.labels({ method: 'GET', path: '/api/threats', status: '200' }).get()).toBe(1);
    });
  });
});
