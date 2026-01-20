/**
 * Distributed Tracing Tests
 * TDD: RED phase - Write failing tests first
 *
 * Tests for distributed tracing with correlation IDs and span tracking
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  Tracer,
  TracerConfig,
  Span,
  SpanContext,
  SpanKind,
  SpanStatus,
  CorrelationIdGenerator,
  SpanExporter,
} from '../../lib/monitoring/tracing';

console.log('Test suite starting...');

describe('Distributed Tracing', () => {
  let tracer: Tracer;

  beforeEach(() => {
    vi.useFakeTimers();
    tracer = new Tracer({
      serviceName: 'test-service',
      environment: 'test',
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('Configuration', () => {
    it('should accept tracer configuration', () => {
      const config: TracerConfig = {
        serviceName: 'my-service',
        environment: 'production',
        sampleRate: 0.5,
      };

      const customTracer = new Tracer(config);
      expect(customTracer.getConfig().serviceName).toBe('my-service');
    });

    it('should use default sample rate of 1.0', () => {
      const customTracer = new Tracer({ serviceName: 'test' });
      expect(customTracer.getConfig().sampleRate).toBe(1.0);
    });
  });

  describe('Correlation ID Generation', () => {
    it('should generate unique correlation IDs', () => {
      const generator = new CorrelationIdGenerator();

      const id1 = generator.generate();
      const id2 = generator.generate();

      expect(id1).not.toBe(id2);
      expect(id1.length).toBeGreaterThan(0);
    });

    it('should generate IDs with prefix', () => {
      const generator = new CorrelationIdGenerator({ prefix: 'req' });

      const id = generator.generate();

      expect(id).toMatch(/^req-/);
    });

    it('should generate IDs with timestamp component', () => {
      const generator = new CorrelationIdGenerator({ includeTimestamp: true });

      const id = generator.generate();

      // Should contain timestamp-like pattern
      expect(id.length).toBeGreaterThan(20);
    });
  });

  describe('Span Creation', () => {
    it('should create a root span', () => {
      const span = tracer.startSpan('root-operation');

      expect(span.name).toBe('root-operation');
      expect(span.traceId).toBeDefined();
      expect(span.spanId).toBeDefined();
      expect(span.parentSpanId).toBeUndefined();
    });

    it('should create child spans', () => {
      const parentSpan = tracer.startSpan('parent-operation');
      const childSpan = tracer.startSpan('child-operation', {
        parent: parentSpan,
      });

      expect(childSpan.traceId).toBe(parentSpan.traceId);
      expect(childSpan.parentSpanId).toBe(parentSpan.spanId);
      expect(childSpan.spanId).not.toBe(parentSpan.spanId);
    });

    it('should support different span kinds', () => {
      const serverSpan = tracer.startSpan('http-request', {
        kind: SpanKind.SERVER,
      });
      const clientSpan = tracer.startSpan('database-query', {
        kind: SpanKind.CLIENT,
      });

      expect(serverSpan.kind).toBe(SpanKind.SERVER);
      expect(clientSpan.kind).toBe(SpanKind.CLIENT);
    });

    it('should create span with initial attributes', () => {
      const span = tracer.startSpan('operation', {
        attributes: {
          'http.method': 'GET',
          'http.url': '/api/users',
        },
      });

      expect(span.attributes['http.method']).toBe('GET');
      expect(span.attributes['http.url']).toBe('/api/users');
    });
  });

  describe('Span Lifecycle', () => {
    it('should record span start time', () => {
      vi.setSystemTime(new Date('2024-01-15T10:00:00.000Z'));

      const span = tracer.startSpan('operation');

      expect(span.startTime).toEqual(new Date('2024-01-15T10:00:00.000Z'));
    });

    it('should record span end time', () => {
      vi.setSystemTime(new Date('2024-01-15T10:00:00.000Z'));
      const span = tracer.startSpan('operation');

      vi.setSystemTime(new Date('2024-01-15T10:00:01.000Z'));
      span.end();

      expect(span.endTime).toEqual(new Date('2024-01-15T10:00:01.000Z'));
      expect(span.duration).toBe(1000);
    });

    it('should calculate span duration', () => {
      vi.setSystemTime(new Date('2024-01-15T10:00:00.000Z'));
      const span = tracer.startSpan('operation');

      vi.advanceTimersByTime(500);
      span.end();

      expect(span.duration).toBe(500);
    });

    it('should prevent ending a span twice', () => {
      const span = tracer.startSpan('operation');
      span.end();

      expect(() => span.end()).toThrow('Span already ended');
    });
  });

  describe('Span Attributes', () => {
    it('should set attributes after creation', () => {
      const span = tracer.startSpan('operation');

      span.setAttribute('user.id', '123');
      span.setAttribute('request.size', 1024);

      expect(span.attributes['user.id']).toBe('123');
      expect(span.attributes['request.size']).toBe(1024);
    });

    it('should set multiple attributes at once', () => {
      const span = tracer.startSpan('operation');

      span.setAttributes({
        'db.type': 'postgresql',
        'db.statement': 'SELECT * FROM users',
        'db.rows_affected': 10,
      });

      expect(span.attributes['db.type']).toBe('postgresql');
      expect(span.attributes['db.rows_affected']).toBe(10);
    });

    it('should not allow setting attributes after span ends', () => {
      const span = tracer.startSpan('operation');
      span.end();

      expect(() => span.setAttribute('key', 'value')).toThrow('Span already ended');
    });
  });

  describe('Span Events', () => {
    it('should record events with timestamp', () => {
      vi.setSystemTime(new Date('2024-01-15T10:00:00.000Z'));
      const span = tracer.startSpan('operation');

      span.addEvent('cache-miss', { key: 'user:123' });

      expect(span.events).toHaveLength(1);
      expect(span.events[0].name).toBe('cache-miss');
      expect(span.events[0].timestamp).toEqual(new Date('2024-01-15T10:00:00.000Z'));
      expect(span.events[0].attributes.key).toBe('user:123');
    });

    it('should record multiple events', () => {
      const span = tracer.startSpan('operation');

      span.addEvent('start-processing');
      span.addEvent('validation-complete');
      span.addEvent('response-sent');

      expect(span.events).toHaveLength(3);
    });
  });

  describe('Span Status', () => {
    it('should set span status to OK', () => {
      const span = tracer.startSpan('operation');

      span.setStatus(SpanStatus.OK);

      expect(span.status).toBe(SpanStatus.OK);
    });

    it('should set span status to ERROR with message', () => {
      const span = tracer.startSpan('operation');

      span.setStatus(SpanStatus.ERROR, 'Database connection failed');

      expect(span.status).toBe(SpanStatus.ERROR);
      expect(span.statusMessage).toBe('Database connection failed');
    });

    it('should record exception as event', () => {
      const span = tracer.startSpan('operation');
      const error = new Error('Something went wrong');

      span.recordException(error);

      expect(span.events).toHaveLength(1);
      expect(span.events[0].name).toBe('exception');
      expect(span.events[0].attributes['exception.message']).toBe('Something went wrong');
      expect(span.status).toBe(SpanStatus.ERROR);
    });
  });

  describe('Context Propagation', () => {
    it('should extract context from headers', () => {
      const headers = {
        'x-trace-id': 'abc123',
        'x-span-id': 'def456',
        'x-parent-span-id': 'ghi789',
      };

      const context = tracer.extractContext(headers);

      expect(context.traceId).toBe('abc123');
      expect(context.spanId).toBe('def456');
      expect(context.parentSpanId).toBe('ghi789');
    });

    it('should inject context into headers', () => {
      const span = tracer.startSpan('operation');
      const headers: Record<string, string> = {};

      tracer.injectContext(span, headers);

      expect(headers['x-trace-id']).toBe(span.traceId);
      expect(headers['x-span-id']).toBe(span.spanId);
    });

    it('should create span from extracted context', () => {
      const headers = {
        'x-trace-id': 'incoming-trace-id',
        'x-span-id': 'incoming-span-id',
      };

      const context = tracer.extractContext(headers);
      const span = tracer.startSpan('downstream-operation', { parent: context });

      expect(span.traceId).toBe('incoming-trace-id');
      expect(span.parentSpanId).toBe('incoming-span-id');
    });
  });

  describe('Sampling', () => {
    it('should sample all spans when rate is 1.0', () => {
      const sampledTracer = new Tracer({
        serviceName: 'test',
        sampleRate: 1.0,
      });

      const spans = Array(10).fill(null).map((_, i) =>
        sampledTracer.startSpan(`span-${i}`)
      );

      expect(spans.every(s => s.sampled)).toBe(true);
    });

    it('should sample no spans when rate is 0', () => {
      const sampledTracer = new Tracer({
        serviceName: 'test',
        sampleRate: 0,
      });

      const spans = Array(10).fill(null).map((_, i) =>
        sampledTracer.startSpan(`span-${i}`)
      );

      expect(spans.every(s => !s.sampled)).toBe(true);
    });

    it('should respect parent sampling decision', () => {
      const sampledTracer = new Tracer({
        serviceName: 'test',
        sampleRate: 0, // Would normally not sample
      });

      // Create a sampled parent context
      const parentContext: SpanContext = {
        traceId: 'trace-123',
        spanId: 'span-456',
        sampled: true, // Force sampled
      };

      const childSpan = sampledTracer.startSpan('child', { parent: parentContext });

      expect(childSpan.sampled).toBe(true);
    });
  });

  describe('Exporter', () => {
    it('should export spans to exporter', () => {
      const exportFn = vi.fn();
      const exporter: SpanExporter = { export: exportFn };

      const exportingTracer = new Tracer({
        serviceName: 'test',
        exporter,
      });

      const span = exportingTracer.startSpan('operation');
      span.end();

      expect(exportFn).toHaveBeenCalledWith(expect.objectContaining({
        name: 'operation',
        traceId: span.traceId,
      }));
    });

    it('should batch export spans', async () => {
      const exportFn = vi.fn();
      const exporter: SpanExporter = { export: exportFn };

      const batchingTracer = new Tracer({
        serviceName: 'test',
        exporter,
        batchSize: 5,
      });

      // Create 4 spans - shouldn't trigger export yet
      for (let i = 0; i < 4; i++) {
        const span = batchingTracer.startSpan(`span-${i}`);
        span.end();
      }

      expect(exportFn).not.toHaveBeenCalled();

      // 5th span triggers batch export
      const span5 = batchingTracer.startSpan('span-5');
      span5.end();

      expect(exportFn).toHaveBeenCalled();
    });

    it('should not export unsampled spans', () => {
      const exportFn = vi.fn();
      const exporter: SpanExporter = { export: exportFn };

      const unsampledTracer = new Tracer({
        serviceName: 'test',
        sampleRate: 0,
        exporter,
      });

      const span = unsampledTracer.startSpan('operation');
      span.end();

      expect(exportFn).not.toHaveBeenCalled();
    });
  });

  describe('Active Span', () => {
    it('should track current active span', () => {
      const span = tracer.startSpan('operation');
      tracer.setActiveSpan(span);

      expect(tracer.getActiveSpan()).toBe(span);
    });

    it('should auto-parent to active span', () => {
      const parentSpan = tracer.startSpan('parent');
      tracer.setActiveSpan(parentSpan);

      const childSpan = tracer.startSpan('child');

      expect(childSpan.parentSpanId).toBe(parentSpan.spanId);
    });

    it('should clear active span on end', () => {
      const span = tracer.startSpan('operation');
      tracer.setActiveSpan(span);

      span.end();
      tracer.clearActiveSpan();

      expect(tracer.getActiveSpan()).toBeUndefined();
    });
  });

  describe('Convenience Methods', () => {
    it('should wrap async function in span', async () => {
      const result = await tracer.withSpan('async-operation', async (span) => {
        span.setAttribute('custom', 'value');
        return 'result';
      });

      expect(result).toBe('result');
    });

    it('should record exception and rethrow', async () => {
      await expect(
        tracer.withSpan('failing-operation', async () => {
          throw new Error('Operation failed');
        })
      ).rejects.toThrow('Operation failed');
    });

    it('should auto-end span after function completes', async () => {
      let capturedSpan: Span | undefined;

      await tracer.withSpan('operation', async (span) => {
        capturedSpan = span;
      });

      expect(capturedSpan?.endTime).toBeDefined();
    });
  });
});

console.log('Test suite complete.');
