/**
 * Request Logging & Tracing Tests
 * TDD: Structured logging with request correlation
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  generateRequestId,
  RequestLogger,
  LogLevel,
  LogEntry,
  createRequestContext,
  RequestContext,
  withRequestLogging,
} from '@/lib/api/request-logger';

describe('Request Logging & Tracing', () => {
  let mockConsole: {
    log: ReturnType<typeof vi.fn>;
    error: ReturnType<typeof vi.fn>;
    warn: ReturnType<typeof vi.fn>;
    info: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00.000Z'));

    mockConsole = {
      log: vi.fn(),
      error: vi.fn(),
      warn: vi.fn(),
      info: vi.fn(),
    };
    vi.spyOn(console, 'log').mockImplementation(mockConsole.log);
    vi.spyOn(console, 'error').mockImplementation(mockConsole.error);
    vi.spyOn(console, 'warn').mockImplementation(mockConsole.warn);
    vi.spyOn(console, 'info').mockImplementation(mockConsole.info);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('generateRequestId', () => {
    it('should generate unique request IDs', () => {
      const id1 = generateRequestId();
      const id2 = generateRequestId();

      expect(id1).not.toBe(id2);
    });

    it('should have correct prefix', () => {
      const id = generateRequestId();

      expect(id).toMatch(/^req_/);
    });

    it('should be reasonable length', () => {
      const id = generateRequestId();

      expect(id.length).toBeGreaterThan(10);
      expect(id.length).toBeLessThan(50);
    });
  });

  describe('createRequestContext', () => {
    it('should create context with request ID', () => {
      const context = createRequestContext('/api/threats', 'GET');

      expect(context.requestId).toMatch(/^req_/);
    });

    it('should include path and method', () => {
      const context = createRequestContext('/api/users', 'POST');

      expect(context.path).toBe('/api/users');
      expect(context.method).toBe('POST');
    });

    it('should record start time', () => {
      const context = createRequestContext('/api/test', 'GET');

      expect(context.startTime).toBeDefined();
      expect(context.startTime).toBeInstanceOf(Date);
    });

    it('should support optional tenant ID', () => {
      const context = createRequestContext('/api/threats', 'GET', 'org_abc123');

      expect(context.tenantId).toBe('org_abc123');
    });

    it('should support optional user ID', () => {
      const context = createRequestContext('/api/threats', 'GET', undefined, 'user_xyz');

      expect(context.userId).toBe('user_xyz');
    });
  });

  describe('RequestLogger', () => {
    let logger: RequestLogger;
    let context: RequestContext;

    beforeEach(() => {
      logger = new RequestLogger();
      context = createRequestContext('/api/test', 'GET', 'org_123', 'user_456');
    });

    describe('log levels', () => {
      it('should log debug messages', () => {
        logger.debug(context, 'Debug message');

        expect(mockConsole.log).toHaveBeenCalled();
        const logArg = mockConsole.log.mock.calls[0][0];
        const parsed = JSON.parse(logArg);
        expect(parsed.level).toBe('debug');
        expect(parsed.message).toBe('Debug message');
      });

      it('should log info messages', () => {
        logger.info(context, 'Info message');

        expect(mockConsole.info).toHaveBeenCalled();
      });

      it('should log warn messages', () => {
        logger.warn(context, 'Warning message');

        expect(mockConsole.warn).toHaveBeenCalled();
      });

      it('should log error messages', () => {
        logger.error(context, 'Error message');

        expect(mockConsole.error).toHaveBeenCalled();
      });
    });

    describe('structured logging', () => {
      it('should output JSON format', () => {
        logger.info(context, 'Test message');

        const logArg = mockConsole.info.mock.calls[0][0];
        expect(() => JSON.parse(logArg)).not.toThrow();
      });

      it('should include request ID in all logs', () => {
        logger.info(context, 'Test');

        const logArg = mockConsole.info.mock.calls[0][0];
        const parsed = JSON.parse(logArg);
        expect(parsed.requestId).toBe(context.requestId);
      });

      it('should include tenant ID in all logs', () => {
        logger.info(context, 'Test');

        const logArg = mockConsole.info.mock.calls[0][0];
        const parsed = JSON.parse(logArg);
        expect(parsed.tenantId).toBe('org_123');
      });

      it('should include timestamp', () => {
        logger.info(context, 'Test');

        const logArg = mockConsole.info.mock.calls[0][0];
        const parsed = JSON.parse(logArg);
        expect(parsed.timestamp).toBe('2024-01-01T00:00:00.000Z');
      });

      it('should include path and method', () => {
        logger.info(context, 'Test');

        const logArg = mockConsole.info.mock.calls[0][0];
        const parsed = JSON.parse(logArg);
        expect(parsed.path).toBe('/api/test');
        expect(parsed.method).toBe('GET');
      });

      it('should support additional metadata', () => {
        logger.info(context, 'User action', { action: 'login', ip: '1.2.3.4' });

        const logArg = mockConsole.info.mock.calls[0][0];
        const parsed = JSON.parse(logArg);
        expect(parsed.action).toBe('login');
        expect(parsed.ip).toBe('1.2.3.4');
      });
    });

    describe('request lifecycle logging', () => {
      it('should log request start', () => {
        logger.logRequestStart(context);

        expect(mockConsole.info).toHaveBeenCalled();
        const logArg = mockConsole.info.mock.calls[0][0];
        const parsed = JSON.parse(logArg);
        expect(parsed.message).toContain('Request started');
      });

      it('should log request end with duration', () => {
        // Advance time by 150ms
        vi.advanceTimersByTime(150);

        logger.logRequestEnd(context, 200);

        expect(mockConsole.info).toHaveBeenCalled();
        const logArg = mockConsole.info.mock.calls[0][0];
        const parsed = JSON.parse(logArg);
        expect(parsed.message).toContain('Request completed');
        expect(parsed.durationMs).toBeGreaterThanOrEqual(150);
        expect(parsed.statusCode).toBe(200);
      });

      it('should log errors with stack trace', () => {
        const error = new Error('Test error');

        logger.logError(context, error);

        expect(mockConsole.error).toHaveBeenCalled();
        const logArg = mockConsole.error.mock.calls[0][0];
        const parsed = JSON.parse(logArg);
        expect(parsed.error).toBe('Test error');
        expect(parsed.stack).toBeDefined();
      });
    });

    describe('log level filtering', () => {
      it('should respect minimum log level', () => {
        const warnLogger = new RequestLogger(LogLevel.WARN);

        warnLogger.debug(context, 'Debug');
        warnLogger.info(context, 'Info');
        warnLogger.warn(context, 'Warn');
        warnLogger.error(context, 'Error');

        expect(mockConsole.log).not.toHaveBeenCalled(); // debug
        expect(mockConsole.info).not.toHaveBeenCalled(); // info
        expect(mockConsole.warn).toHaveBeenCalled(); // warn
        expect(mockConsole.error).toHaveBeenCalled(); // error
      });
    });
  });

  describe('withRequestLogging', () => {
    let logger: RequestLogger;

    beforeEach(() => {
      logger = new RequestLogger();
    });

    it('should wrap handler with logging', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK', { status: 200 }));
      const wrappedHandler = withRequestLogging(handler, logger);

      await wrappedHandler(new Request('http://test.com/api/test'));

      // Should log start and end
      expect(mockConsole.info).toHaveBeenCalledTimes(2);
    });

    it('should add request ID header to response', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK', { status: 200 }));
      const wrappedHandler = withRequestLogging(handler, logger);

      const response = await wrappedHandler(new Request('http://test.com/api/test'));

      expect(response.headers.get('X-Request-ID')).toMatch(/^req_/);
    });

    it('should log errors and return error response', async () => {
      const handler = vi.fn().mockRejectedValue(new Error('Handler failed'));
      const wrappedHandler = withRequestLogging(handler, logger);

      const response = await wrappedHandler(new Request('http://test.com/api/test'));

      expect(response.status).toBe(500);
      expect(mockConsole.error).toHaveBeenCalled();
    });
  });

  describe('Sensitive data masking', () => {
    let logger: RequestLogger;
    let context: RequestContext;

    beforeEach(() => {
      logger = new RequestLogger();
      context = createRequestContext('/api/auth/login', 'POST');
    });

    it('should mask authorization headers', () => {
      logger.info(context, 'Request headers', {
        headers: {
          Authorization: 'Bearer secret-token-123',
          'Content-Type': 'application/json',
        },
      });

      const logArg = mockConsole.info.mock.calls[0][0];
      const parsed = JSON.parse(logArg);
      expect(parsed.headers.Authorization).toBe('[REDACTED]');
      expect(parsed.headers['Content-Type']).toBe('application/json');
    });

    it('should mask password fields', () => {
      logger.info(context, 'Login attempt', {
        email: 'user@example.com',
        password: 'secret123',
      });

      const logArg = mockConsole.info.mock.calls[0][0];
      const parsed = JSON.parse(logArg);
      expect(parsed.email).toBe('user@example.com');
      expect(parsed.password).toBe('[REDACTED]');
    });

    it('should mask tokens', () => {
      logger.info(context, 'Token refresh', {
        accessToken: 'eyJhbG...',
        refreshToken: 'ref_xyz123',
      });

      const logArg = mockConsole.info.mock.calls[0][0];
      const parsed = JSON.parse(logArg);
      expect(parsed.accessToken).toBe('[REDACTED]');
      expect(parsed.refreshToken).toBe('[REDACTED]');
    });
  });

  describe('Performance metrics', () => {
    let logger: RequestLogger;
    let context: RequestContext;

    beforeEach(() => {
      logger = new RequestLogger();
      context = createRequestContext('/api/threats', 'GET');
    });

    it('should track request duration', () => {
      vi.advanceTimersByTime(250);

      logger.logRequestEnd(context, 200);

      const logArg = mockConsole.info.mock.calls[0][0];
      const parsed = JSON.parse(logArg);
      expect(parsed.durationMs).toBeGreaterThanOrEqual(250);
    });

    it('should warn on slow requests', () => {
      vi.advanceTimersByTime(5000); // 5 seconds

      logger.logRequestEnd(context, 200);

      // Should log warning about slow request
      const lastCall = mockConsole.warn.mock.calls[0]?.[0] || mockConsole.info.mock.calls[0][0];
      const parsed = JSON.parse(lastCall);
      expect(parsed.slow).toBe(true);
    });
  });
});
