/**
 * Request Logging & Tracing Module
 *
 * Provides structured logging with request correlation for API debugging and monitoring.
 * Includes sensitive data masking and performance tracking.
 */

import { nanoid } from 'nanoid';
import { errorToResponse } from './errors';

/**
 * Log levels (ordered by severity)
 */
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

/**
 * Request context for correlation
 */
export interface RequestContext {
  requestId: string;
  path: string;
  method: string;
  startTime: Date;
  tenantId?: string;
  userId?: string;
}

/**
 * Log entry structure
 */
export interface LogEntry {
  timestamp: string;
  level: string;
  requestId: string;
  path: string;
  method: string;
  message: string;
  tenantId?: string;
  userId?: string;
  [key: string]: unknown;
}

/**
 * Sensitive field names that should be masked in logs
 */
const SENSITIVE_FIELDS = [
  'password',
  'token',
  'accessToken',
  'refreshToken',
  'access_token',
  'refresh_token',
  'secret',
  'apiKey',
  'api_key',
  'authorization',
  'Authorization',
  'cookie',
  'Cookie',
];

/**
 * Threshold for slow request warning (ms)
 */
const SLOW_REQUEST_THRESHOLD_MS = 3000;

/**
 * Generate a unique request ID
 */
export function generateRequestId(): string {
  return `req_${nanoid(21)}`;
}

/**
 * Create a request context
 */
export function createRequestContext(
  path: string,
  method: string,
  tenantId?: string,
  userId?: string
): RequestContext {
  return {
    requestId: generateRequestId(),
    path,
    method,
    startTime: new Date(),
    tenantId,
    userId,
  };
}

/**
 * Mask sensitive data in an object
 */
function maskSensitiveData<T extends Record<string, unknown>>(data: T): T {
  if (!data || typeof data !== 'object') {
    return data;
  }

  const masked = { ...data } as Record<string, unknown>;

  for (const key of Object.keys(masked)) {
    if (SENSITIVE_FIELDS.some((field) => key.toLowerCase().includes(field.toLowerCase()))) {
      masked[key] = '[REDACTED]';
    } else if (typeof masked[key] === 'object' && masked[key] !== null) {
      masked[key] = maskSensitiveData(masked[key] as Record<string, unknown>);
    }
  }

  return masked as T;
}

/**
 * Request logger with structured JSON output
 */
export class RequestLogger {
  private minLevel: LogLevel;

  constructor(minLevel: LogLevel = LogLevel.DEBUG) {
    this.minLevel = minLevel;
  }

  /**
   * Create a log entry
   */
  private createEntry(
    level: string,
    context: RequestContext,
    message: string,
    metadata?: Record<string, unknown>
  ): LogEntry {
    const maskedMetadata = metadata ? maskSensitiveData(metadata) : {};

    return {
      timestamp: new Date().toISOString(),
      level,
      requestId: context.requestId,
      path: context.path,
      method: context.method,
      message,
      ...(context.tenantId && { tenantId: context.tenantId }),
      ...(context.userId && { userId: context.userId }),
      ...maskedMetadata,
    };
  }

  /**
   * Write log to console
   */
  private write(
    level: LogLevel,
    levelName: string,
    context: RequestContext,
    message: string,
    metadata?: Record<string, unknown>
  ): void {
    if (level < this.minLevel) {
      return;
    }

    const entry = this.createEntry(levelName, context, message, metadata);
    const json = JSON.stringify(entry);

    switch (level) {
      case LogLevel.DEBUG:
        console.log(json);
        break;
      case LogLevel.INFO:
        console.info(json);
        break;
      case LogLevel.WARN:
        console.warn(json);
        break;
      case LogLevel.ERROR:
        console.error(json);
        break;
    }
  }

  /**
   * Log debug message
   */
  debug(context: RequestContext, message: string, metadata?: Record<string, unknown>): void {
    this.write(LogLevel.DEBUG, 'debug', context, message, metadata);
  }

  /**
   * Log info message
   */
  info(context: RequestContext, message: string, metadata?: Record<string, unknown>): void {
    this.write(LogLevel.INFO, 'info', context, message, metadata);
  }

  /**
   * Log warning message
   */
  warn(context: RequestContext, message: string, metadata?: Record<string, unknown>): void {
    this.write(LogLevel.WARN, 'warn', context, message, metadata);
  }

  /**
   * Log error message
   */
  error(context: RequestContext, message: string, metadata?: Record<string, unknown>): void {
    this.write(LogLevel.ERROR, 'error', context, message, metadata);
  }

  /**
   * Log request start
   */
  logRequestStart(context: RequestContext): void {
    this.info(context, `Request started: ${context.method} ${context.path}`);
  }

  /**
   * Log request end with duration
   */
  logRequestEnd(context: RequestContext, statusCode: number): void {
    const durationMs = Date.now() - context.startTime.getTime();
    const isSlow = durationMs >= SLOW_REQUEST_THRESHOLD_MS;

    const metadata = {
      durationMs,
      statusCode,
      slow: isSlow,
    };

    const message = `Request completed: ${context.method} ${context.path} - ${statusCode}`;

    if (isSlow) {
      this.warn(context, message, metadata);
    } else {
      this.info(context, message, metadata);
    }
  }

  /**
   * Log error with stack trace
   */
  logError(context: RequestContext, error: Error): void {
    this.error(context, `Request error: ${error.message}`, {
      error: error.message,
      stack: error.stack,
    });
  }
}

/**
 * Default logger instance
 */
export const defaultLogger = new RequestLogger(
  process.env.LOG_LEVEL === 'debug' ? LogLevel.DEBUG : LogLevel.INFO
);

/**
 * Wrap a request handler with logging
 */
export function withRequestLogging(
  handler: (request: Request) => Promise<Response>,
  logger: RequestLogger = defaultLogger
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const context = createRequestContext(url.pathname, request.method);

    logger.logRequestStart(context);

    try {
      const response = await handler(request);

      // Add request ID header to response
      const headers = new Headers(response.headers);
      headers.set('X-Request-ID', context.requestId);

      logger.logRequestEnd(context, response.status);

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    } catch (error) {
      logger.logError(context, error instanceof Error ? error : new Error(String(error)));

      const errorResponse = errorToResponse(error);
      const headers = new Headers(errorResponse.headers);
      headers.set('X-Request-ID', context.requestId);

      return new Response(errorResponse.body, {
        status: errorResponse.status,
        statusText: errorResponse.statusText,
        headers,
      });
    }
  };
}
