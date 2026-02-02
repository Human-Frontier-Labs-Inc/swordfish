/**
 * Unified Structured Logger
 *
 * Production-grade logging with:
 * - Structured JSON output for log aggregation
 * - Correlation ID tracking across requests and async operations
 * - Sensitive data masking
 * - Log level filtering based on environment
 * - Integration with request context and observability
 */

import { nanoid } from 'nanoid';

/**
 * Log levels ordered by severity
 */
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  FATAL = 4,
}

/**
 * Log level names for output
 */
const LOG_LEVEL_NAMES: Record<LogLevel, string> = {
  [LogLevel.DEBUG]: 'debug',
  [LogLevel.INFO]: 'info',
  [LogLevel.WARN]: 'warn',
  [LogLevel.ERROR]: 'error',
  [LogLevel.FATAL]: 'fatal',
};

/**
 * Log context for correlation
 */
export interface LogContext {
  /** Unique request/operation ID */
  correlationId?: string;
  /** Tenant ID for multi-tenant isolation */
  tenantId?: string;
  /** User ID if authenticated */
  userId?: string;
  /** Service/module name */
  service?: string;
  /** HTTP request info if applicable */
  request?: {
    method?: string;
    path?: string;
    userAgent?: string;
  };
  /** Additional context metadata */
  [key: string]: unknown;
}

/**
 * Structured log entry
 */
export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  correlationId?: string;
  tenantId?: string;
  userId?: string;
  service?: string;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  duration?: number;
  [key: string]: unknown;
}

/**
 * Sensitive field patterns that should be masked
 */
const SENSITIVE_PATTERNS = [
  /password/i,
  /token/i,
  /secret/i,
  /apikey/i,
  /api_key/i,
  /authorization/i,
  /cookie/i,
  /credential/i,
  /private/i,
  /ssn/i,
  /credit.?card/i,
  /cvv/i,
  /pin/i,
];

/**
 * Check if a field name is sensitive
 */
function isSensitiveField(fieldName: string): boolean {
  return SENSITIVE_PATTERNS.some((pattern) => pattern.test(fieldName));
}

/**
 * Recursively mask sensitive data in an object
 */
function maskSensitiveData(data: unknown, depth = 0): unknown {
  if (depth > 10) return '[MAX_DEPTH]';

  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    // Mask if it looks like a JWT or API key
    if (data.match(/^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/)) {
      return '[JWT_REDACTED]';
    }
    if (data.match(/^[a-zA-Z0-9]{32,}$/)) {
      return '[API_KEY_REDACTED]';
    }
    return data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => maskSensitiveData(item, depth + 1));
  }

  if (typeof data === 'object') {
    const masked: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      if (isSensitiveField(key)) {
        masked[key] = '[REDACTED]';
      } else {
        masked[key] = maskSensitiveData(value, depth + 1);
      }
    }
    return masked;
  }

  return data;
}

/**
 * Format error for logging
 */
function formatError(error: Error): { name: string; message: string; stack?: string } {
  return {
    name: error.name,
    message: error.message,
    stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined,
  };
}

/**
 * Get minimum log level from environment
 */
function getMinLevel(): LogLevel {
  const envLevel = process.env.LOG_LEVEL?.toLowerCase();
  switch (envLevel) {
    case 'debug':
      return LogLevel.DEBUG;
    case 'info':
      return LogLevel.INFO;
    case 'warn':
    case 'warning':
      return LogLevel.WARN;
    case 'error':
      return LogLevel.ERROR;
    case 'fatal':
      return LogLevel.FATAL;
    default:
      return process.env.NODE_ENV === 'production' ? LogLevel.INFO : LogLevel.DEBUG;
  }
}

/**
 * Logger class with context binding
 */
export class Logger {
  private context: LogContext;
  private minLevel: LogLevel;
  private service: string;

  constructor(service: string, context: LogContext = {}) {
    this.service = service;
    this.context = context;
    this.minLevel = getMinLevel();
  }

  /**
   * Create a child logger with additional context
   */
  child(additionalContext: LogContext): Logger {
    const childLogger = new Logger(this.service, {
      ...this.context,
      ...additionalContext,
    });
    childLogger.minLevel = this.minLevel;
    return childLogger;
  }

  /**
   * Create logger with correlation ID
   */
  withCorrelationId(correlationId: string): Logger {
    return this.child({ correlationId });
  }

  /**
   * Create logger with tenant context
   */
  withTenant(tenantId: string): Logger {
    return this.child({ tenantId });
  }

  /**
   * Create logger with user context
   */
  withUser(userId: string): Logger {
    return this.child({ userId });
  }

  /**
   * Write log entry
   */
  private write(level: LogLevel, message: string, meta?: Record<string, unknown>): void {
    if (level < this.minLevel) {
      return;
    }

    const maskedMeta = meta ? (maskSensitiveData(meta) as Record<string, unknown>) : undefined;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: LOG_LEVEL_NAMES[level],
      message,
      service: this.service,
      ...(this.context.correlationId && { correlationId: this.context.correlationId }),
      ...(this.context.tenantId && { tenantId: this.context.tenantId }),
      ...(this.context.userId && { userId: this.context.userId }),
      ...maskedMeta,
    };

    const json = JSON.stringify(entry);

    switch (level) {
      case LogLevel.DEBUG:
        console.debug(json);
        break;
      case LogLevel.INFO:
        console.info(json);
        break;
      case LogLevel.WARN:
        console.warn(json);
        break;
      case LogLevel.ERROR:
      case LogLevel.FATAL:
        console.error(json);
        break;
    }
  }

  /**
   * Log debug message
   */
  debug(message: string, meta?: Record<string, unknown>): void {
    this.write(LogLevel.DEBUG, message, meta);
  }

  /**
   * Log info message
   */
  info(message: string, meta?: Record<string, unknown>): void {
    this.write(LogLevel.INFO, message, meta);
  }

  /**
   * Log warning message
   */
  warn(message: string, meta?: Record<string, unknown>): void {
    this.write(LogLevel.WARN, message, meta);
  }

  /**
   * Log error message
   */
  error(message: string, errorOrMeta?: Error | Record<string, unknown>, meta?: Record<string, unknown>): void {
    let finalMeta: Record<string, unknown> = meta ?? {};

    if (errorOrMeta instanceof Error) {
      finalMeta = { ...finalMeta, error: formatError(errorOrMeta) };
    } else if (errorOrMeta) {
      finalMeta = { ...finalMeta, ...errorOrMeta };
    }

    this.write(LogLevel.ERROR, message, finalMeta);
  }

  /**
   * Log fatal message
   */
  fatal(message: string, errorOrMeta?: Error | Record<string, unknown>, meta?: Record<string, unknown>): void {
    let finalMeta: Record<string, unknown> = meta ?? {};

    if (errorOrMeta instanceof Error) {
      finalMeta = { ...finalMeta, error: formatError(errorOrMeta) };
    } else if (errorOrMeta) {
      finalMeta = { ...finalMeta, ...errorOrMeta };
    }

    this.write(LogLevel.FATAL, message, finalMeta);
  }

  /**
   * Time an async operation
   */
  async time<T>(
    operation: string,
    fn: () => Promise<T>,
    meta?: Record<string, unknown>
  ): Promise<T> {
    const start = Date.now();
    try {
      const result = await fn();
      const duration = Date.now() - start;
      this.info(`${operation} completed`, { ...meta, duration, success: true });
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      this.error(`${operation} failed`, error instanceof Error ? error : new Error(String(error)), {
        ...meta,
        duration,
        success: false,
      });
      throw error;
    }
  }

  /**
   * Time a sync operation
   */
  timeSync<T>(
    operation: string,
    fn: () => T,
    meta?: Record<string, unknown>
  ): T {
    const start = Date.now();
    try {
      const result = fn();
      const duration = Date.now() - start;
      this.info(`${operation} completed`, { ...meta, duration, success: true });
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      this.error(`${operation} failed`, error instanceof Error ? error : new Error(String(error)), {
        ...meta,
        duration,
        success: false,
      });
      throw error;
    }
  }
}

/**
 * Generate a correlation ID
 */
export function generateCorrelationId(): string {
  return `cid_${nanoid(21)}`;
}

/**
 * Create a logger for a service
 */
export function createLogger(service: string, context?: LogContext): Logger {
  return new Logger(service, context);
}

/**
 * Pre-configured loggers for common services
 */
export const loggers = {
  detection: createLogger('detection'),
  webhook: createLogger('webhook'),
  worker: createLogger('worker'),
  api: createLogger('api'),
  auth: createLogger('auth'),
  integration: createLogger('integration'),
  threatIntel: createLogger('threat-intel'),
  remediation: createLogger('remediation'),
  queue: createLogger('queue'),
  db: createLogger('database'),
};

/**
 * Default logger instance
 */
export const log = createLogger('swordfish');
