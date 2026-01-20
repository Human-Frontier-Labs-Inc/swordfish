/**
 * Error Tracking System
 *
 * Provides comprehensive error tracking with context capture,
 * categorization, fingerprinting, and flexible reporting.
 */

import { randomUUID } from 'crypto';

export enum ErrorSeverity {
  DEBUG = 'debug',
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

export enum ErrorCategory {
  UNKNOWN = 'unknown',
  DATABASE = 'database',
  NETWORK = 'network',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  VALIDATION = 'validation',
  EXTERNAL_SERVICE = 'external_service',
  CONFIGURATION = 'configuration',
  RATE_LIMIT = 'rate_limit',
  TIMEOUT = 'timeout',
}

export interface ErrorContext {
  userId?: string;
  tenantId?: string;
  requestId?: string;
  fingerprint?: string;
  unhandled?: boolean;
  additionalData?: Record<string, unknown>;
}

export interface Breadcrumb {
  type: string;
  message: string;
  data?: Record<string, unknown>;
  timestamp: Date;
}

export interface ErrorEvent {
  id: string;
  name: string;
  message: string;
  stack?: string;
  severity: ErrorSeverity;
  category: ErrorCategory;
  timestamp: Date;
  fingerprint: string;
  context?: ErrorContext;
  breadcrumbs?: Breadcrumb[];
  serviceName?: string;
  environment?: string;
  version?: string;
}

export interface ErrorReporter {
  report(event: ErrorEvent): void | Promise<void>;
  flush?(): Promise<void>;
}

export interface ErrorTrackerConfig {
  serviceName: string;
  environment?: string;
  version?: string;
  maxBreadcrumbs?: number;
  sampleRate?: number;
  reporters?: ErrorReporter[];
}

export interface ErrorGroup {
  fingerprint: string;
  count: number;
  firstOccurrence: Date;
  lastOccurrence: Date;
  sample: ErrorEvent;
}

/**
 * Main error tracker class
 */
export class ErrorTracker {
  private config: Required<Omit<ErrorTrackerConfig, 'reporters'>> & { reporters: ErrorReporter[] };
  private breadcrumbs: Breadcrumb[] = [];

  constructor(config: ErrorTrackerConfig) {
    if (!config.serviceName || config.serviceName.trim() === '') {
      throw new Error('Service name is required');
    }

    if (config.sampleRate !== undefined && (config.sampleRate < 0 || config.sampleRate > 1)) {
      throw new Error('Sample rate must be between 0 and 1');
    }

    this.config = {
      serviceName: config.serviceName,
      environment: config.environment ?? 'development',
      version: config.version ?? '0.0.0',
      maxBreadcrumbs: config.maxBreadcrumbs ?? 100,
      sampleRate: config.sampleRate ?? 1.0,
      reporters: config.reporters ?? [],
    };
  }

  getConfig(): ErrorTrackerConfig {
    return {
      serviceName: this.config.serviceName,
      environment: this.config.environment,
      version: this.config.version,
      maxBreadcrumbs: this.config.maxBreadcrumbs,
      sampleRate: this.config.sampleRate,
    };
  }

  captureError(
    error: Error,
    context: ErrorContext = {},
    severity: ErrorSeverity = ErrorSeverity.ERROR
  ): ErrorEvent | null {
    // Check sample rate
    if (Math.random() >= this.config.sampleRate) {
      return null;
    }

    const category = this.categorizeError(error);
    const fingerprint = context.fingerprint ?? this.generateFingerprint(error);

    const event: ErrorEvent = {
      id: randomUUID(),
      name: error.name,
      message: error.message,
      stack: error.stack,
      severity,
      category,
      timestamp: new Date(),
      fingerprint,
      context,
      breadcrumbs: [...this.breadcrumbs],
      serviceName: this.config.serviceName,
      environment: this.config.environment,
      version: this.config.version,
    };

    // Report to all reporters
    this.reportError(event);

    return event;
  }

  addBreadcrumb(breadcrumb: Omit<Breadcrumb, 'timestamp'>): void {
    const crumb: Breadcrumb = {
      ...breadcrumb,
      timestamp: new Date(),
    };

    this.breadcrumbs.push(crumb);

    // Trim to max breadcrumbs
    while (this.breadcrumbs.length > this.config.maxBreadcrumbs) {
      this.breadcrumbs.shift();
    }
  }

  getBreadcrumbs(): Breadcrumb[] {
    return [...this.breadcrumbs];
  }

  clearBreadcrumbs(): void {
    this.breadcrumbs = [];
  }

  handleUncaughtException(error: Error): void {
    this.captureError(
      error,
      { unhandled: true },
      ErrorSeverity.CRITICAL
    );
  }

  async shutdown(): Promise<void> {
    const flushPromises = this.config.reporters
      .filter((r) => r.flush)
      .map((r) => r.flush!());
    await Promise.all(flushPromises);
  }

  private categorizeError(error: Error): ErrorCategory {
    const message = error.message.toLowerCase();

    if (
      message.includes('econnrefused') ||
      message.includes('connection') ||
      message.includes('database') ||
      message.includes('postgres') ||
      message.includes('mysql') ||
      message.includes('mongo')
    ) {
      return ErrorCategory.DATABASE;
    }

    if (
      message.includes('unauthorized') ||
      message.includes('authentication') ||
      message.includes('invalid token') ||
      message.includes('jwt')
    ) {
      return ErrorCategory.AUTHENTICATION;
    }

    if (
      message.includes('forbidden') ||
      message.includes('permission') ||
      message.includes('access denied')
    ) {
      return ErrorCategory.AUTHORIZATION;
    }

    if (
      message.includes('validation') ||
      message.includes('required') ||
      message.includes('invalid')
    ) {
      return ErrorCategory.VALIDATION;
    }

    if (
      message.includes('timeout') ||
      message.includes('timed out')
    ) {
      return ErrorCategory.TIMEOUT;
    }

    if (
      message.includes('rate limit') ||
      message.includes('too many requests')
    ) {
      return ErrorCategory.RATE_LIMIT;
    }

    if (
      message.includes('network') ||
      message.includes('fetch') ||
      message.includes('socket')
    ) {
      return ErrorCategory.NETWORK;
    }

    return ErrorCategory.UNKNOWN;
  }

  private generateFingerprint(error: Error): string {
    // Create fingerprint based on error type and message
    const base = `${error.name}:${error.message}`;

    // Simple hash function
    let hash = 0;
    for (let i = 0; i < base.length; i++) {
      const char = base.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }

    return `fp-${Math.abs(hash).toString(16)}`;
  }

  private reportError(event: ErrorEvent): void {
    for (const reporter of this.config.reporters) {
      try {
        reporter.report(event);
      } catch {
        // Don't let reporter errors affect the application
      }
    }
  }
}

/**
 * Console reporter for development
 */
export interface ConsoleReporterConfig {
  includeStack?: boolean;
}

export class ConsoleReporter implements ErrorReporter {
  private config: ConsoleReporterConfig;

  constructor(config: ConsoleReporterConfig = {}) {
    this.config = config;
  }

  report(event: ErrorEvent): void {
    const parts = [
      `[${event.severity.toUpperCase()}]`,
      `[${event.category}]`,
      `${event.name}: ${event.message}`,
    ];

    if (this.config.includeStack && event.stack) {
      parts.push(`\n${event.stack}`);
    }

    console.error(parts.join(' '));
  }
}

/**
 * Webhook reporter for external error tracking services
 */
export interface WebhookReporterConfig {
  url: string;
  headers?: Record<string, string>;
  batchSize?: number;
  flushInterval?: number;
}

export class WebhookReporter implements ErrorReporter {
  private config: Required<WebhookReporterConfig>;
  private batch: ErrorEvent[] = [];
  private flushTimer?: ReturnType<typeof setTimeout>;

  constructor(config: WebhookReporterConfig) {
    this.config = {
      url: config.url,
      headers: config.headers ?? {},
      batchSize: config.batchSize ?? 10,
      flushInterval: config.flushInterval ?? 5000,
    };
  }

  async report(event: ErrorEvent): Promise<void> {
    this.batch.push(event);

    if (this.batch.length >= this.config.batchSize) {
      await this.flush();
    } else if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.config.flushInterval);
    }
  }

  async flush(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }

    if (this.batch.length === 0) return;

    const events = [...this.batch];
    this.batch = [];

    try {
      await fetch(this.config.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.config.headers,
        },
        body: JSON.stringify({ events }),
      });
    } catch (error) {
      console.warn('Failed to send error events to webhook:', error);
    }
  }
}

/**
 * Error aggregator for grouping and analyzing errors
 */
export class ErrorAggregator {
  private groups: Map<string, ErrorGroup> = new Map();
  private events: ErrorEvent[] = [];

  add(event: ErrorEvent): void {
    this.events.push(event);

    const existing = this.groups.get(event.fingerprint);
    if (existing) {
      existing.count++;
      if (event.timestamp > existing.lastOccurrence) {
        existing.lastOccurrence = event.timestamp;
      }
      if (event.timestamp < existing.firstOccurrence) {
        existing.firstOccurrence = event.timestamp;
      }
    } else {
      this.groups.set(event.fingerprint, {
        fingerprint: event.fingerprint,
        count: 1,
        firstOccurrence: event.timestamp,
        lastOccurrence: event.timestamp,
        sample: event,
      });
    }
  }

  getGroups(): ErrorGroup[] {
    return Array.from(this.groups.values());
  }

  getTopErrors(limit: number): ErrorGroup[] {
    return this.getGroups()
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  getByCategory(category: ErrorCategory): ErrorGroup[] {
    return this.getGroups().filter((g) => g.sample.category === category);
  }

  getErrorRate(windowMs: number): number {
    const now = Date.now();
    const windowStart = now - windowMs;

    const recentEvents = this.events.filter(
      (e) => e.timestamp.getTime() >= windowStart
    );

    return recentEvents.length / (windowMs / 1000);
  }

  clearOlderThan(maxAgeMs: number): void {
    const cutoff = Date.now() - maxAgeMs;

    // Remove old events
    this.events = this.events.filter((e) => e.timestamp.getTime() >= cutoff);

    // Rebuild groups from remaining events
    this.groups.clear();
    for (const event of this.events) {
      const existing = this.groups.get(event.fingerprint);
      if (existing) {
        existing.count++;
        if (event.timestamp > existing.lastOccurrence) {
          existing.lastOccurrence = event.timestamp;
        }
        if (event.timestamp < existing.firstOccurrence) {
          existing.firstOccurrence = event.timestamp;
        }
      } else {
        this.groups.set(event.fingerprint, {
          fingerprint: event.fingerprint,
          count: 1,
          firstOccurrence: event.timestamp,
          lastOccurrence: event.timestamp,
          sample: event,
        });
      }
    }
  }
}
