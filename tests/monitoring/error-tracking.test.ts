/**
 * Error Tracking Integration Tests
 * TDD: RED phase - Write failing tests first
 *
 * Error tracking system for capturing, categorizing, and reporting errors
 * with context for debugging and monitoring.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  ErrorTracker,
  ErrorTrackerConfig,
  ErrorEvent,
  ErrorSeverity,
  ErrorContext,
  ErrorCategory,
  ErrorReporter,
  ConsoleReporter,
  WebhookReporter,
  ErrorAggregator,
} from '../../lib/monitoring/error-tracking';

describe('Error Tracking', () => {
  let tracker: ErrorTracker;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('ErrorTracker Configuration', () => {
    it('should accept error tracker configuration', () => {
      const config: ErrorTrackerConfig = {
        serviceName: 'swordfish-api',
        environment: 'production',
        version: '1.0.0',
        maxBreadcrumbs: 50,
        sampleRate: 1.0,
      };

      tracker = new ErrorTracker(config);
      expect(tracker.getConfig()).toEqual(config);
    });

    it('should use default values for optional parameters', () => {
      tracker = new ErrorTracker({ serviceName: 'test-service' });
      const config = tracker.getConfig();

      expect(config.environment).toBe('development');
      expect(config.maxBreadcrumbs).toBe(100);
      expect(config.sampleRate).toBe(1.0);
    });

    it('should validate configuration parameters', () => {
      expect(() => new ErrorTracker({
        serviceName: '',
      })).toThrow('Service name is required');

      expect(() => new ErrorTracker({
        serviceName: 'test',
        sampleRate: 1.5,
      })).toThrow('Sample rate must be between 0 and 1');
    });
  });

  describe('Error Capture', () => {
    beforeEach(() => {
      tracker = new ErrorTracker({ serviceName: 'test-service' });
    });

    it('should capture Error objects', () => {
      const error = new Error('Test error');
      const event = tracker.captureError(error);

      expect(event.message).toBe('Test error');
      expect(event.name).toBe('Error');
      expect(event.stack).toBeDefined();
    });

    it('should capture errors with context', () => {
      const error = new Error('Database connection failed');
      const context: ErrorContext = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        requestId: 'req-789',
        additionalData: {
          database: 'postgres',
          host: 'db.example.com',
        },
      };

      const event = tracker.captureError(error, context);

      expect(event.context?.userId).toBe('user-123');
      expect(event.context?.tenantId).toBe('tenant-456');
      expect(event.context?.additionalData?.database).toBe('postgres');
    });

    it('should capture errors with severity levels', () => {
      const error = new Error('Critical failure');

      const event = tracker.captureError(error, {}, ErrorSeverity.CRITICAL);

      expect(event.severity).toBe(ErrorSeverity.CRITICAL);
    });

    it('should auto-categorize common error types', () => {
      const dbError = new Error('ECONNREFUSED: Connection refused');
      const authError = new Error('Unauthorized: Invalid token');
      const validationError = new Error('Validation failed: email is required');

      const dbEvent = tracker.captureError(dbError);
      const authEvent = tracker.captureError(authError);
      const validationEvent = tracker.captureError(validationError);

      expect(dbEvent.category).toBe(ErrorCategory.DATABASE);
      expect(authEvent.category).toBe(ErrorCategory.AUTHENTICATION);
      expect(validationEvent.category).toBe(ErrorCategory.VALIDATION);
    });

    it('should capture custom error types', () => {
      class CustomApiError extends Error {
        constructor(message: string, public statusCode: number) {
          super(message);
          this.name = 'CustomApiError';
        }
      }

      const error = new CustomApiError('Not Found', 404);
      const event = tracker.captureError(error);

      expect(event.name).toBe('CustomApiError');
      expect(event.message).toBe('Not Found');
    });

    it('should respect sample rate', () => {
      tracker = new ErrorTracker({
        serviceName: 'test-service',
        sampleRate: 0.5,
      });

      // Mock Math.random to return predictable values
      const mockRandom = vi.spyOn(Math, 'random');
      mockRandom.mockReturnValueOnce(0.3); // Should capture (< 0.5)
      mockRandom.mockReturnValueOnce(0.7); // Should not capture (>= 0.5)

      const event1 = tracker.captureError(new Error('Error 1'));
      const event2 = tracker.captureError(new Error('Error 2'));

      expect(event1).toBeDefined();
      expect(event2).toBeNull();
    });

    it('should generate unique event IDs', () => {
      const event1 = tracker.captureError(new Error('Error 1'));
      const event2 = tracker.captureError(new Error('Error 2'));

      expect(event1?.id).toBeDefined();
      expect(event2?.id).toBeDefined();
      expect(event1?.id).not.toBe(event2?.id);
    });

    it('should include timestamp', () => {
      const now = Date.now();
      vi.setSystemTime(now);

      const event = tracker.captureError(new Error('Test'));

      expect(event?.timestamp).toBeInstanceOf(Date);
      expect(event?.timestamp.getTime()).toBe(now);
    });
  });

  describe('Breadcrumbs', () => {
    beforeEach(() => {
      tracker = new ErrorTracker({
        serviceName: 'test-service',
        maxBreadcrumbs: 5,
      });
    });

    it('should add breadcrumbs', () => {
      tracker.addBreadcrumb({
        type: 'navigation',
        message: 'User navigated to /dashboard',
        data: { path: '/dashboard' },
      });

      const breadcrumbs = tracker.getBreadcrumbs();
      expect(breadcrumbs).toHaveLength(1);
      expect(breadcrumbs[0].message).toBe('User navigated to /dashboard');
    });

    it('should include breadcrumbs in error events', () => {
      tracker.addBreadcrumb({ type: 'http', message: 'GET /api/users' });
      tracker.addBreadcrumb({ type: 'http', message: 'POST /api/auth' });

      const event = tracker.captureError(new Error('Request failed'));

      expect(event?.breadcrumbs).toHaveLength(2);
    });

    it('should limit breadcrumbs to max count', () => {
      for (let i = 0; i < 10; i++) {
        tracker.addBreadcrumb({ type: 'log', message: `Log ${i}` });
      }

      const breadcrumbs = tracker.getBreadcrumbs();
      expect(breadcrumbs).toHaveLength(5);
      expect(breadcrumbs[0].message).toBe('Log 5'); // Oldest kept
    });

    it('should clear breadcrumbs', () => {
      tracker.addBreadcrumb({ type: 'log', message: 'Test' });
      tracker.clearBreadcrumbs();

      expect(tracker.getBreadcrumbs()).toHaveLength(0);
    });

    it('should timestamp breadcrumbs', () => {
      const now = Date.now();
      vi.setSystemTime(now);

      tracker.addBreadcrumb({ type: 'log', message: 'Test' });

      const breadcrumbs = tracker.getBreadcrumbs();
      expect(breadcrumbs[0].timestamp.getTime()).toBe(now);
    });
  });

  describe('Error Fingerprinting', () => {
    beforeEach(() => {
      tracker = new ErrorTracker({ serviceName: 'test-service' });
    });

    it('should generate consistent fingerprints for same errors', () => {
      const error1 = new Error('Database connection failed');
      const error2 = new Error('Database connection failed');

      const event1 = tracker.captureError(error1);
      const event2 = tracker.captureError(error2);

      expect(event1?.fingerprint).toBe(event2?.fingerprint);
    });

    it('should generate different fingerprints for different errors', () => {
      const error1 = new Error('Database connection failed');
      const error2 = new Error('Authentication failed');

      const event1 = tracker.captureError(error1);
      const event2 = tracker.captureError(error2);

      expect(event1?.fingerprint).not.toBe(event2?.fingerprint);
    });

    it('should allow custom fingerprinting', () => {
      const event = tracker.captureError(
        new Error('User error'),
        { fingerprint: 'custom-fingerprint-123' }
      );

      expect(event?.fingerprint).toBe('custom-fingerprint-123');
    });
  });

  describe('Error Reporters', () => {
    describe('ConsoleReporter', () => {
      it('should log errors to console', () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const reporter = new ConsoleReporter();

        const event: ErrorEvent = {
          id: 'event-123',
          name: 'Error',
          message: 'Test error',
          severity: ErrorSeverity.ERROR,
          category: ErrorCategory.UNKNOWN,
          timestamp: new Date(),
          fingerprint: 'fp-123',
        };

        reporter.report(event);

        expect(consoleSpy).toHaveBeenCalled();
        expect(consoleSpy.mock.calls[0][0]).toContain('Test error');
      });

      it('should format error with stack trace', () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const reporter = new ConsoleReporter({ includeStack: true });

        const error = new Error('Test');
        const event: ErrorEvent = {
          id: 'event-123',
          name: 'Error',
          message: 'Test error',
          stack: error.stack,
          severity: ErrorSeverity.ERROR,
          category: ErrorCategory.UNKNOWN,
          timestamp: new Date(),
          fingerprint: 'fp-123',
        };

        reporter.report(event);

        const output = consoleSpy.mock.calls[0][0];
        expect(output).toContain('Error');
      });
    });

    describe('WebhookReporter', () => {
      it('should send errors to webhook endpoint', async () => {
        const fetchMock = vi.fn().mockResolvedValue({ ok: true });
        global.fetch = fetchMock;

        const reporter = new WebhookReporter({
          url: 'https://errors.example.com/webhook',
          headers: { 'Authorization': 'Bearer token' },
          batchSize: 1, // Send immediately
        });

        const event: ErrorEvent = {
          id: 'event-123',
          name: 'Error',
          message: 'Test error',
          severity: ErrorSeverity.ERROR,
          category: ErrorCategory.UNKNOWN,
          timestamp: new Date(),
          fingerprint: 'fp-123',
        };

        await reporter.report(event);

        expect(fetchMock).toHaveBeenCalledWith(
          'https://errors.example.com/webhook',
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Authorization': 'Bearer token',
              'Content-Type': 'application/json',
            }),
          })
        );
      });

      it('should batch errors for efficiency', async () => {
        vi.useRealTimers();
        const fetchMock = vi.fn().mockResolvedValue({ ok: true });
        global.fetch = fetchMock;

        const reporter = new WebhookReporter({
          url: 'https://errors.example.com/webhook',
          batchSize: 3,
          flushInterval: 100,
        });

        const event: ErrorEvent = {
          id: 'event-123',
          name: 'Error',
          message: 'Test error',
          severity: ErrorSeverity.ERROR,
          category: ErrorCategory.UNKNOWN,
          timestamp: new Date(),
          fingerprint: 'fp-123',
        };

        // Send 3 events to trigger batch
        reporter.report(event);
        reporter.report({ ...event, id: 'event-124' });
        reporter.report({ ...event, id: 'event-125' });

        // Wait for batch to be sent
        await new Promise(resolve => setTimeout(resolve, 50));

        expect(fetchMock).toHaveBeenCalledTimes(1);
        const body = JSON.parse(fetchMock.mock.calls[0][1].body);
        expect(body.events).toHaveLength(3);
      });

      it('should handle webhook failures gracefully', async () => {
        const fetchMock = vi.fn().mockRejectedValue(new Error('Network error'));
        global.fetch = fetchMock;
        const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

        const reporter = new WebhookReporter({
          url: 'https://errors.example.com/webhook',
          batchSize: 1, // Send immediately
        });

        const event: ErrorEvent = {
          id: 'event-123',
          name: 'Error',
          message: 'Test error',
          severity: ErrorSeverity.ERROR,
          category: ErrorCategory.UNKNOWN,
          timestamp: new Date(),
          fingerprint: 'fp-123',
        };

        await reporter.report(event);

        // Should not throw, but should warn
        expect(consoleSpy).toHaveBeenCalled();
      });
    });
  });

  describe('ErrorAggregator', () => {
    let aggregator: ErrorAggregator;

    beforeEach(() => {
      aggregator = new ErrorAggregator();
    });

    it('should aggregate errors by fingerprint', () => {
      const event1: ErrorEvent = {
        id: 'event-1',
        name: 'Error',
        message: 'DB Error',
        severity: ErrorSeverity.ERROR,
        category: ErrorCategory.DATABASE,
        timestamp: new Date(),
        fingerprint: 'fp-db',
      };

      const event2: ErrorEvent = {
        id: 'event-2',
        name: 'Error',
        message: 'DB Error',
        severity: ErrorSeverity.ERROR,
        category: ErrorCategory.DATABASE,
        timestamp: new Date(),
        fingerprint: 'fp-db',
      };

      aggregator.add(event1);
      aggregator.add(event2);

      const groups = aggregator.getGroups();
      expect(groups).toHaveLength(1);
      expect(groups[0].count).toBe(2);
    });

    it('should track first and last occurrence', () => {
      const now = Date.now();
      vi.setSystemTime(now);

      const event1: ErrorEvent = {
        id: 'event-1',
        name: 'Error',
        message: 'Test',
        severity: ErrorSeverity.ERROR,
        category: ErrorCategory.UNKNOWN,
        timestamp: new Date(now),
        fingerprint: 'fp-test',
      };

      aggregator.add(event1);

      vi.setSystemTime(now + 1000);

      const event2: ErrorEvent = {
        id: 'event-2',
        name: 'Error',
        message: 'Test',
        severity: ErrorSeverity.ERROR,
        category: ErrorCategory.UNKNOWN,
        timestamp: new Date(now + 1000),
        fingerprint: 'fp-test',
      };

      aggregator.add(event2);

      const groups = aggregator.getGroups();
      expect(groups[0].firstOccurrence.getTime()).toBe(now);
      expect(groups[0].lastOccurrence.getTime()).toBe(now + 1000);
    });

    it('should get top errors by count', () => {
      for (let i = 0; i < 10; i++) {
        aggregator.add({
          id: `event-${i}`,
          name: 'Error',
          message: 'Common error',
          severity: ErrorSeverity.ERROR,
          category: ErrorCategory.UNKNOWN,
          timestamp: new Date(),
          fingerprint: 'fp-common',
        });
      }

      for (let i = 0; i < 5; i++) {
        aggregator.add({
          id: `event-rare-${i}`,
          name: 'Error',
          message: 'Rare error',
          severity: ErrorSeverity.ERROR,
          category: ErrorCategory.UNKNOWN,
          timestamp: new Date(),
          fingerprint: 'fp-rare',
        });
      }

      const top = aggregator.getTopErrors(1);
      expect(top[0].fingerprint).toBe('fp-common');
      expect(top[0].count).toBe(10);
    });

    it('should filter by category', () => {
      aggregator.add({
        id: 'event-1',
        name: 'Error',
        message: 'DB Error',
        severity: ErrorSeverity.ERROR,
        category: ErrorCategory.DATABASE,
        timestamp: new Date(),
        fingerprint: 'fp-db',
      });

      aggregator.add({
        id: 'event-2',
        name: 'Error',
        message: 'Auth Error',
        severity: ErrorSeverity.ERROR,
        category: ErrorCategory.AUTHENTICATION,
        timestamp: new Date(),
        fingerprint: 'fp-auth',
      });

      const dbErrors = aggregator.getByCategory(ErrorCategory.DATABASE);
      expect(dbErrors).toHaveLength(1);
      expect(dbErrors[0].sample.category).toBe(ErrorCategory.DATABASE);
    });

    it('should calculate error rate over time window', () => {
      const now = Date.now();
      vi.setSystemTime(now);

      // Add 10 errors over 10 seconds
      for (let i = 0; i < 10; i++) {
        vi.setSystemTime(now + i * 1000);
        aggregator.add({
          id: `event-${i}`,
          name: 'Error',
          message: 'Test',
          severity: ErrorSeverity.ERROR,
          category: ErrorCategory.UNKNOWN,
          timestamp: new Date(),
          fingerprint: 'fp-test',
        });
      }

      vi.setSystemTime(now + 10000);
      const rate = aggregator.getErrorRate(10000); // Last 10 seconds

      expect(rate).toBe(1); // 10 errors / 10 seconds = 1 error/second
    });

    it('should clear old data', () => {
      const now = Date.now();
      vi.setSystemTime(now);

      aggregator.add({
        id: 'event-old',
        name: 'Error',
        message: 'Old error',
        severity: ErrorSeverity.ERROR,
        category: ErrorCategory.UNKNOWN,
        timestamp: new Date(now - 3600000), // 1 hour ago
        fingerprint: 'fp-old',
      });

      aggregator.add({
        id: 'event-new',
        name: 'Error',
        message: 'New error',
        severity: ErrorSeverity.ERROR,
        category: ErrorCategory.UNKNOWN,
        timestamp: new Date(now),
        fingerprint: 'fp-new',
      });

      aggregator.clearOlderThan(1800000); // Clear older than 30 minutes

      const groups = aggregator.getGroups();
      expect(groups).toHaveLength(1);
      expect(groups[0].fingerprint).toBe('fp-new');
    });
  });

  describe('Integration', () => {
    it('should integrate tracker with reporters', async () => {
      const mockReporter: ErrorReporter = {
        report: vi.fn().mockResolvedValue(undefined),
      };

      tracker = new ErrorTracker({
        serviceName: 'test-service',
        reporters: [mockReporter],
      });

      const error = new Error('Integration test error');
      tracker.captureError(error);

      expect(mockReporter.report).toHaveBeenCalledTimes(1);
      expect(mockReporter.report).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Integration test error',
        })
      );
    });

    it('should handle multiple reporters', async () => {
      const reporter1: ErrorReporter = { report: vi.fn().mockResolvedValue(undefined) };
      const reporter2: ErrorReporter = { report: vi.fn().mockResolvedValue(undefined) };

      tracker = new ErrorTracker({
        serviceName: 'test-service',
        reporters: [reporter1, reporter2],
      });

      tracker.captureError(new Error('Test'));

      expect(reporter1.report).toHaveBeenCalledTimes(1);
      expect(reporter2.report).toHaveBeenCalledTimes(1);
    });

    it('should continue reporting even if one reporter fails', async () => {
      const failingReporter: ErrorReporter = {
        report: vi.fn().mockRejectedValue(new Error('Reporter failed')),
      };
      const workingReporter: ErrorReporter = {
        report: vi.fn().mockResolvedValue(undefined),
      };

      tracker = new ErrorTracker({
        serviceName: 'test-service',
        reporters: [failingReporter, workingReporter],
      });

      // Should not throw
      tracker.captureError(new Error('Test'));

      expect(workingReporter.report).toHaveBeenCalled();
    });

    it('should provide global error handler', () => {
      tracker = new ErrorTracker({ serviceName: 'test-service' });

      const mockCapture = vi.spyOn(tracker, 'captureError');

      const unhandledError = new Error('Unhandled');
      tracker.handleUncaughtException(unhandledError);

      expect(mockCapture).toHaveBeenCalledWith(
        unhandledError,
        expect.objectContaining({ unhandled: true }),
        ErrorSeverity.CRITICAL
      );
    });

    it('should flush pending reports on shutdown', async () => {
      vi.useRealTimers();

      const flushMock = vi.fn().mockResolvedValue(undefined);
      const reporter: ErrorReporter = {
        report: vi.fn().mockResolvedValue(undefined),
        flush: flushMock,
      };

      tracker = new ErrorTracker({
        serviceName: 'test-service',
        reporters: [reporter],
      });

      await tracker.shutdown();

      expect(flushMock).toHaveBeenCalled();
    });
  });
});
