/**
 * Distributed Tracing
 *
 * Provides distributed tracing with correlation IDs, span tracking,
 * and context propagation for observability.
 */

import { randomUUID } from 'crypto';

export enum SpanKind {
  INTERNAL = 'internal',
  SERVER = 'server',
  CLIENT = 'client',
  PRODUCER = 'producer',
  CONSUMER = 'consumer',
}

export enum SpanStatus {
  UNSET = 'unset',
  OK = 'ok',
  ERROR = 'error',
}

export interface SpanEvent {
  name: string;
  timestamp: Date;
  attributes: Record<string, unknown>;
}

export interface SpanContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  sampled?: boolean;
}

export interface SpanExporter {
  export(span: SpanData): void;
}

export interface SpanData {
  name: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  kind: SpanKind;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  status: SpanStatus;
  statusMessage?: string;
  attributes: Record<string, unknown>;
  events: SpanEvent[];
  sampled: boolean;
}

export interface TracerConfig {
  serviceName: string;
  environment?: string;
  sampleRate?: number;
  exporter?: SpanExporter;
  batchSize?: number;
}

export interface SpanOptions {
  parent?: Span | SpanContext;
  kind?: SpanKind;
  attributes?: Record<string, unknown>;
}

export interface CorrelationIdConfig {
  prefix?: string;
  includeTimestamp?: boolean;
}

/**
 * Correlation ID Generator
 */
export class CorrelationIdGenerator {
  private config: CorrelationIdConfig;

  constructor(config: CorrelationIdConfig = {}) {
    this.config = config;
  }

  generate(): string {
    const uuid = randomUUID().replace(/-/g, '');

    let id = uuid;

    if (this.config.includeTimestamp) {
      const timestamp = Date.now().toString(36);
      id = `${timestamp}-${uuid}`;
    }

    if (this.config.prefix) {
      id = `${this.config.prefix}-${id}`;
    }

    return id;
  }
}

/**
 * Span implementation
 */
export class Span implements SpanContext {
  readonly name: string;
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly kind: SpanKind;
  readonly startTime: Date;
  readonly sampled: boolean;

  private _endTime?: Date;
  private _duration?: number;
  private _status: SpanStatus = SpanStatus.UNSET;
  private _statusMessage?: string;
  private _attributes: Record<string, unknown> = {};
  private _events: SpanEvent[] = [];
  private _ended = false;
  private onEnd?: (span: Span) => void;

  constructor(
    name: string,
    traceId: string,
    spanId: string,
    options: {
      parentSpanId?: string;
      kind?: SpanKind;
      attributes?: Record<string, unknown>;
      sampled?: boolean;
      onEnd?: (span: Span) => void;
    } = {}
  ) {
    this.name = name;
    this.traceId = traceId;
    this.spanId = spanId;
    this.parentSpanId = options.parentSpanId;
    this.kind = options.kind ?? SpanKind.INTERNAL;
    this.startTime = new Date();
    this.sampled = options.sampled ?? true;
    this._attributes = options.attributes ?? {};
    this.onEnd = options.onEnd;
  }

  get endTime(): Date | undefined {
    return this._endTime;
  }

  get duration(): number | undefined {
    return this._duration;
  }

  get status(): SpanStatus {
    return this._status;
  }

  get statusMessage(): string | undefined {
    return this._statusMessage;
  }

  get attributes(): Record<string, unknown> {
    return { ...this._attributes };
  }

  get events(): SpanEvent[] {
    return [...this._events];
  }

  setAttribute(key: string, value: unknown): void {
    if (this._ended) {
      throw new Error('Span already ended');
    }
    this._attributes[key] = value;
  }

  setAttributes(attributes: Record<string, unknown>): void {
    if (this._ended) {
      throw new Error('Span already ended');
    }
    Object.assign(this._attributes, attributes);
  }

  addEvent(name: string, attributes: Record<string, unknown> = {}): void {
    if (this._ended) {
      throw new Error('Span already ended');
    }
    this._events.push({
      name,
      timestamp: new Date(),
      attributes,
    });
  }

  setStatus(status: SpanStatus, message?: string): void {
    this._status = status;
    this._statusMessage = message;
  }

  recordException(error: Error): void {
    this.addEvent('exception', {
      'exception.type': error.name,
      'exception.message': error.message,
      'exception.stacktrace': error.stack,
    });
    this.setStatus(SpanStatus.ERROR, error.message);
  }

  end(): void {
    if (this._ended) {
      throw new Error('Span already ended');
    }
    this._ended = true;
    this._endTime = new Date();
    this._duration = this._endTime.getTime() - this.startTime.getTime();

    if (this.onEnd) {
      this.onEnd(this);
    }
  }

  toData(): SpanData {
    return {
      name: this.name,
      traceId: this.traceId,
      spanId: this.spanId,
      parentSpanId: this.parentSpanId,
      kind: this.kind,
      startTime: this.startTime,
      endTime: this._endTime,
      duration: this._duration,
      status: this._status,
      statusMessage: this._statusMessage,
      attributes: this._attributes,
      events: this._events,
      sampled: this.sampled,
    };
  }
}

/**
 * Tracer implementation
 */
export class Tracer {
  private config: Required<Omit<TracerConfig, 'exporter'>> & { exporter?: SpanExporter };
  private idGenerator = new CorrelationIdGenerator();
  private activeSpan?: Span;
  private pendingSpans: SpanData[] = [];

  constructor(config: TracerConfig) {
    this.config = {
      serviceName: config.serviceName,
      environment: config.environment ?? 'development',
      sampleRate: config.sampleRate ?? 1.0,
      exporter: config.exporter,
      batchSize: config.batchSize ?? 1,
    };
  }

  getConfig(): { serviceName: string; sampleRate: number } {
    return {
      serviceName: this.config.serviceName,
      sampleRate: this.config.sampleRate,
    };
  }

  startSpan(name: string, options: SpanOptions = {}): Span {
    let traceId: string;
    let parentSpanId: string | undefined;
    let sampled: boolean;

    if (options.parent) {
      // Use parent context
      traceId = options.parent.traceId;
      parentSpanId = options.parent.spanId;
      sampled = options.parent.sampled ?? this.shouldSample();
    } else if (this.activeSpan) {
      // Auto-parent to active span
      traceId = this.activeSpan.traceId;
      parentSpanId = this.activeSpan.spanId;
      sampled = this.activeSpan.sampled;
    } else {
      // New root span
      traceId = this.generateId();
      sampled = this.shouldSample();
    }

    const spanId = this.generateId();

    const span = new Span(name, traceId, spanId, {
      parentSpanId,
      kind: options.kind,
      attributes: options.attributes,
      sampled,
      onEnd: (s) => this.onSpanEnd(s),
    });

    return span;
  }

  extractContext(headers: Record<string, string>): SpanContext {
    return {
      traceId: headers['x-trace-id'] || this.generateId(),
      spanId: headers['x-span-id'] || this.generateId(),
      parentSpanId: headers['x-parent-span-id'],
      sampled: headers['x-sampled'] !== 'false',
    };
  }

  injectContext(span: Span, headers: Record<string, string>): void {
    headers['x-trace-id'] = span.traceId;
    headers['x-span-id'] = span.spanId;
    if (span.parentSpanId) {
      headers['x-parent-span-id'] = span.parentSpanId;
    }
    headers['x-sampled'] = String(span.sampled);
  }

  setActiveSpan(span: Span): void {
    this.activeSpan = span;
  }

  getActiveSpan(): Span | undefined {
    return this.activeSpan;
  }

  clearActiveSpan(): void {
    this.activeSpan = undefined;
  }

  async withSpan<T>(name: string, fn: (span: Span) => Promise<T>): Promise<T> {
    const span = this.startSpan(name);
    this.setActiveSpan(span);

    try {
      const result = await fn(span);
      span.setStatus(SpanStatus.OK);
      return result;
    } catch (error) {
      if (error instanceof Error) {
        span.recordException(error);
      }
      throw error;
    } finally {
      span.end();
      this.clearActiveSpan();
    }
  }

  private onSpanEnd(span: Span): void {
    if (!span.sampled) {
      return;
    }

    if (!this.config.exporter) {
      return;
    }

    this.pendingSpans.push(span.toData());

    if (this.pendingSpans.length >= this.config.batchSize) {
      this.flushSpans();
    }
  }

  private flushSpans(): void {
    if (!this.config.exporter || this.pendingSpans.length === 0) {
      return;
    }

    for (const spanData of this.pendingSpans) {
      this.config.exporter.export(spanData);
    }

    this.pendingSpans = [];
  }

  private generateId(): string {
    return this.idGenerator.generate();
  }

  private shouldSample(): boolean {
    return Math.random() < this.config.sampleRate;
  }
}
