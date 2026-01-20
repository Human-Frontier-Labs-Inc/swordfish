/**
 * Metrics Collection Module
 *
 * Provides Prometheus-compatible metrics for monitoring and alerting.
 * Supports counters, gauges, and histograms with labels.
 */

/**
 * Metric types
 */
export enum MetricType {
  COUNTER = 'counter',
  GAUGE = 'gauge',
  HISTOGRAM = 'histogram',
}

/**
 * Base metric interface
 */
interface BaseMetric {
  name: string;
  help: string;
  type: MetricType;
  labelNames: string[];
}

/**
 * Label values type
 */
type Labels = Record<string, string>;

/**
 * Histogram options
 */
interface HistogramOptions {
  buckets?: number[];
}

/**
 * Default histogram buckets
 */
const DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

/**
 * Counter metric implementation
 */
export class Counter implements BaseMetric {
  name: string;
  help: string;
  type = MetricType.COUNTER;
  labelNames: string[];

  private values: Map<string, number> = new Map();

  constructor(name: string, help: string, labelNames: string[] = []) {
    this.name = name;
    this.help = help;
    this.labelNames = labelNames;
    this.values.set('', 0);
  }

  private getLabelKey(labels: Labels): string {
    if (this.labelNames.length === 0) return '';
    return this.labelNames.map((name) => `${name}="${labels[name] || ''}"`).join(',');
  }

  labels(labels: Labels): Counter {
    const key = this.getLabelKey(labels);
    if (!this.values.has(key)) {
      this.values.set(key, 0);
    }
    const values = this.values;
    return {
      ...this,
      inc: (value = 1) => {
        if (value < 0) throw new Error('Counter cannot be decremented');
        values.set(key, (values.get(key) || 0) + value);
      },
      get: () => {
        return values.get(key) || 0;
      },
    } as Counter;
  }

  inc(value = 1): void {
    if (value < 0) throw new Error('Counter cannot be decremented');
    this.values.set('', (this.values.get('') || 0) + value);
  }

  get(): number {
    return this.values.get('') || 0;
  }

  reset(): void {
    this.values.clear();
    this.values.set('', 0);
  }

  getAll(): Map<string, number> {
    return new Map(this.values);
  }
}

/**
 * Gauge metric implementation
 */
export class Gauge implements BaseMetric {
  name: string;
  help: string;
  type = MetricType.GAUGE;
  labelNames: string[];

  private values: Map<string, number> = new Map();

  constructor(name: string, help: string, labelNames: string[] = []) {
    this.name = name;
    this.help = help;
    this.labelNames = labelNames;
    this.values.set('', 0);
  }

  private getLabelKey(labels: Labels): string {
    if (this.labelNames.length === 0) return '';
    return this.labelNames.map((name) => `${name}="${labels[name] || ''}"`).join(',');
  }

  labels(labels: Labels): Gauge {
    const key = this.getLabelKey(labels);
    if (!this.values.has(key)) {
      this.values.set(key, 0);
    }
    const values = this.values;
    return {
      ...this,
      set: (value: number) => {
        values.set(key, value);
      },
      inc: (value = 1) => {
        values.set(key, (values.get(key) || 0) + value);
      },
      dec: (value = 1) => {
        values.set(key, (values.get(key) || 0) - value);
      },
      get: () => {
        return values.get(key) || 0;
      },
    } as Gauge;
  }

  set(value: number): void {
    this.values.set('', value);
  }

  inc(value = 1): void {
    this.values.set('', (this.values.get('') || 0) + value);
  }

  dec(value = 1): void {
    this.values.set('', (this.values.get('') || 0) - value);
  }

  get(): number {
    return this.values.get('') || 0;
  }

  reset(): void {
    this.values.clear();
    this.values.set('', 0);
  }

  getAll(): Map<string, number> {
    return new Map(this.values);
  }
}

/**
 * Histogram stats
 */
interface HistogramStats {
  count: number;
  sum: number;
  min: number;
  max: number;
}

/**
 * Histogram metric implementation
 */
export class Histogram implements BaseMetric {
  name: string;
  help: string;
  type = MetricType.HISTOGRAM;
  labelNames: string[];

  private buckets: number[];
  private observations: Map<string, number[]> = new Map();
  private bucketCounts: Map<string, Map<number, number>> = new Map();

  constructor(
    name: string,
    help: string,
    labelNames: string[] = [],
    options: HistogramOptions = {}
  ) {
    this.name = name;
    this.help = help;
    this.labelNames = labelNames;
    this.buckets = options.buckets || DEFAULT_BUCKETS;
    this.initBucket('');
  }

  private initBucket(key: string): void {
    this.observations.set(key, []);
    const bucketMap = new Map<number, number>();
    for (const b of this.buckets) {
      bucketMap.set(b, 0);
    }
    bucketMap.set(Infinity, 0);
    this.bucketCounts.set(key, bucketMap);
  }

  private getLabelKey(labels: Labels): string {
    if (this.labelNames.length === 0) return '';
    return this.labelNames.map((name) => `${name}="${labels[name] || ''}"`).join(',');
  }

  labels(labels: Labels): Histogram {
    const key = this.getLabelKey(labels);
    if (!this.observations.has(key)) {
      this.initBucket(key);
    }
    return {
      ...this,
      observe: (value: number) => {
        this.observeWithKey(key, value);
      },
      getStats: () => {
        return this.getStatsForKey(key);
      },
      startTimer: () => {
        return this.startTimerForKey(key);
      },
    } as Histogram;
  }

  private observeWithKey(key: string, value: number): void {
    const obs = this.observations.get(key);
    if (obs) {
      obs.push(value);
    }

    const buckets = this.bucketCounts.get(key);
    if (buckets) {
      for (const [bucket, count] of buckets) {
        if (value <= bucket) {
          buckets.set(bucket, count + 1);
        }
      }
    }
  }

  observe(value: number): void {
    this.observeWithKey('', value);
  }

  private getStatsForKey(key: string): HistogramStats {
    const obs = this.observations.get(key) || [];
    if (obs.length === 0) {
      return { count: 0, sum: 0, min: 0, max: 0 };
    }

    return {
      count: obs.length,
      sum: obs.reduce((a, b) => a + b, 0),
      min: Math.min(...obs),
      max: Math.max(...obs),
    };
  }

  getStats(): HistogramStats {
    return this.getStatsForKey('');
  }

  percentile(p: number): number {
    const obs = this.observations.get('') || [];
    if (obs.length === 0) return 0;

    const sorted = [...obs].sort((a, b) => a - b);
    const index = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  }

  getBuckets(): Map<number, number> {
    return new Map(this.bucketCounts.get('') || new Map());
  }

  private startTimerForKey(key: string): () => number {
    const start = process.hrtime.bigint();
    return () => {
      const end = process.hrtime.bigint();
      const duration = Number(end - start) / 1e9;
      this.observeWithKey(key, duration);
      return duration;
    };
  }

  startTimer(): () => number {
    return this.startTimerForKey('');
  }

  reset(): void {
    this.observations.clear();
    this.bucketCounts.clear();
    this.initBucket('');
  }
}

/**
 * Metrics registry
 */
export class MetricsRegistry {
  private metrics: Map<string, BaseMetric> = new Map();

  register(metric: BaseMetric): void {
    if (this.metrics.has(metric.name)) {
      throw new Error(`Metric ${metric.name} already registered`);
    }
    this.metrics.set(metric.name, metric);
  }

  getMetricNames(): string[] {
    return Array.from(this.metrics.keys());
  }

  getMetric(name: string): BaseMetric | undefined {
    return this.metrics.get(name);
  }

  reset(): void {
    for (const metric of this.metrics.values()) {
      if ('reset' in metric && typeof metric.reset === 'function') {
        (metric as Counter | Gauge | Histogram).reset();
      }
    }
  }

  toPrometheusFormat(): string {
    const lines: string[] = [];

    for (const metric of this.metrics.values()) {
      lines.push(`# HELP ${metric.name} ${metric.help}`);
      lines.push(`# TYPE ${metric.name} ${metric.type}`);

      if (metric instanceof Counter || metric instanceof Gauge) {
        const values = metric.getAll();
        for (const [labels, value] of values) {
          if (labels) {
            lines.push(`${metric.name}{${labels}} ${value}`);
          } else {
            lines.push(`${metric.name} ${value}`);
          }
        }
      } else if (metric instanceof Histogram) {
        const stats = metric.getStats();
        lines.push(`${metric.name}_count ${stats.count}`);
        lines.push(`${metric.name}_sum ${stats.sum}`);

        const buckets = metric.getBuckets();
        for (const [le, count] of buckets) {
          const leStr = le === Infinity ? '+Inf' : String(le);
          lines.push(`${metric.name}_bucket{le="${leStr}"} ${count}`);
        }
      }
    }

    return lines.join('\n');
  }

  toJSON(): Record<string, { type: string; value: number | HistogramStats }> {
    const result: Record<string, { type: string; value: number | HistogramStats }> = {};

    for (const metric of this.metrics.values()) {
      if (metric instanceof Counter || metric instanceof Gauge) {
        result[metric.name] = {
          type: metric.type,
          value: metric.get(),
        };
      } else if (metric instanceof Histogram) {
        result[metric.name] = {
          type: metric.type,
          value: metric.getStats(),
        };
      }
    }

    return result;
  }
}

/**
 * Metrics collector
 */
export class MetricsCollector {
  private registry: MetricsRegistry;

  constructor() {
    this.registry = new MetricsRegistry();
  }

  counter(name: string, help: string, labelNames: string[] = []): Counter {
    const counter = new Counter(name, help, labelNames);
    this.registry.register(counter);
    return counter;
  }

  gauge(name: string, help: string, labelNames: string[] = []): Gauge {
    const gauge = new Gauge(name, help, labelNames);
    this.registry.register(gauge);
    return gauge;
  }

  histogram(
    name: string,
    help: string,
    labelNames: string[] = [],
    options: HistogramOptions = {}
  ): Histogram {
    const histogram = new Histogram(name, help, labelNames, options);
    this.registry.register(histogram);
    return histogram;
  }

  getRegistry(): MetricsRegistry {
    return this.registry;
  }

  collectDefaultMetrics(): void {
    // Process metrics
    this.gauge('process_cpu_seconds_total', 'Total CPU time spent');
    this.gauge('process_memory_bytes', 'Process memory usage');

    // Node.js metrics
    this.gauge('nodejs_heap_size_bytes', 'Node.js heap size');
    this.gauge('nodejs_event_loop_lag_seconds', 'Event loop lag');
  }
}

/**
 * Create a metrics collector instance
 */
export function createMetricsCollector(): MetricsCollector {
  return new MetricsCollector();
}

/**
 * Default metrics collector
 */
export const defaultMetrics = createMetricsCollector();

/**
 * System metrics interface
 */
export interface SystemMetrics {
  system: {
    uptime: number;
    memoryUsage: {
      heapUsed: number;
      heapTotal: number;
      external: number;
      rss: number;
    };
    cpuUsage: {
      user: number;
      system: number;
    };
  };
  application?: {
    emailsProcessed?: number;
    threatsDetected?: number;
    activeIntegrations?: number;
    queueDepth?: number;
  };
  timestamp: string;
}

/**
 * Collect system and application metrics
 */
export async function collectMetrics(tenantId?: string): Promise<SystemMetrics> {
  const memUsage = process.memoryUsage();
  const cpuUsage = process.cpuUsage();

  const metrics: SystemMetrics = {
    system: {
      uptime: process.uptime(),
      memoryUsage: {
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        external: memUsage.external,
        rss: memUsage.rss,
      },
      cpuUsage: {
        user: cpuUsage.user / 1e6,
        system: cpuUsage.system / 1e6,
      },
    },
    timestamp: new Date().toISOString(),
  };

  // Application-specific metrics would be collected here
  // For now, return system metrics
  return metrics;
}

/**
 * Format metrics in Prometheus exposition format
 */
export function formatPrometheusMetrics(metrics: SystemMetrics): string {
  const lines: string[] = [];

  // System metrics
  lines.push('# HELP process_uptime_seconds Process uptime in seconds');
  lines.push('# TYPE process_uptime_seconds gauge');
  lines.push(`process_uptime_seconds ${metrics.system.uptime}`);

  lines.push('# HELP process_heap_bytes Process heap memory in bytes');
  lines.push('# TYPE process_heap_bytes gauge');
  lines.push(`process_heap_bytes{type="used"} ${metrics.system.memoryUsage.heapUsed}`);
  lines.push(`process_heap_bytes{type="total"} ${metrics.system.memoryUsage.heapTotal}`);

  lines.push('# HELP process_memory_rss_bytes Process resident set size in bytes');
  lines.push('# TYPE process_memory_rss_bytes gauge');
  lines.push(`process_memory_rss_bytes ${metrics.system.memoryUsage.rss}`);

  lines.push('# HELP process_cpu_seconds_total Total CPU time');
  lines.push('# TYPE process_cpu_seconds_total counter');
  lines.push(`process_cpu_seconds_total{type="user"} ${metrics.system.cpuUsage.user}`);
  lines.push(`process_cpu_seconds_total{type="system"} ${metrics.system.cpuUsage.system}`);

  // Add registry metrics if available
  const registryMetrics = defaultMetrics.getRegistry().toPrometheusFormat();
  if (registryMetrics) {
    lines.push('');
    lines.push(registryMetrics);
  }

  return lines.join('\n');
}
