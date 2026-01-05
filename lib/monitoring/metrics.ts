/**
 * Production Monitoring Metrics
 *
 * Collect and expose system metrics for monitoring dashboards
 */

import { sql } from '@/lib/db';

export interface SystemMetrics {
  timestamp: Date;
  system: SystemHealth;
  email: EmailMetrics;
  detection: DetectionMetrics;
  performance: PerformanceMetrics;
  integrations: IntegrationMetrics;
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime: number;
  version: string;
  environment: string;
}

export interface EmailMetrics {
  processed24h: number;
  processedHour: number;
  queueDepth: number;
  avgProcessingTime: number;
}

export interface DetectionMetrics {
  threatsDetected24h: number;
  threatsBlocked24h: number;
  quarantined24h: number;
  falsePositives24h: number;
  avgConfidence: number;
}

export interface PerformanceMetrics {
  avgResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  errorRate: number;
  requestsPerMinute: number;
}

export interface IntegrationMetrics {
  googleWorkspace: IntegrationStatus;
  microsoft365: IntegrationStatus;
  webhooksActive: number;
  apiRequestsHour: number;
}

export interface IntegrationStatus {
  connected: number;
  syncing: number;
  errored: number;
  lastSyncTime?: Date;
}

// In-memory metrics store for high-frequency data
const metricsStore = {
  requestCount: 0,
  errorCount: 0,
  responseTimes: [] as number[],
  lastReset: Date.now(),
};

/**
 * Record a request metric
 */
export function recordRequest(responseTime: number, isError: boolean): void {
  metricsStore.requestCount++;
  if (isError) metricsStore.errorCount++;
  metricsStore.responseTimes.push(responseTime);

  // Keep only last 1000 response times
  if (metricsStore.responseTimes.length > 1000) {
    metricsStore.responseTimes.shift();
  }

  // Reset counters every hour
  if (Date.now() - metricsStore.lastReset > 3600000) {
    metricsStore.requestCount = 0;
    metricsStore.errorCount = 0;
    metricsStore.lastReset = Date.now();
  }
}

/**
 * Collect all system metrics
 */
export async function collectMetrics(tenantId?: string): Promise<SystemMetrics> {
  const [email, detection, integrations] = await Promise.all([
    collectEmailMetrics(tenantId),
    collectDetectionMetrics(tenantId),
    collectIntegrationMetrics(tenantId),
  ]);

  return {
    timestamp: new Date(),
    system: {
      status: determineHealthStatus(email, detection),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
    },
    email,
    detection,
    performance: collectPerformanceMetrics(),
    integrations,
  };
}

async function collectEmailMetrics(tenantId?: string): Promise<EmailMetrics> {
  try {
    let stats24h: Array<Record<string, unknown>>;
    let statsHour: Array<Record<string, unknown>>;

    if (tenantId) {
      stats24h = await sql`
        SELECT
          COUNT(*) as total,
          COALESCE(AVG(processing_time_ms), 0) as avg_time
        FROM email_verdicts
        WHERE tenant_id = ${tenantId} AND created_at > NOW() - INTERVAL '24 hours'
      `;
      statsHour = await sql`
        SELECT COUNT(*) as total
        FROM email_verdicts
        WHERE tenant_id = ${tenantId} AND created_at > NOW() - INTERVAL '1 hour'
      `;
    } else {
      stats24h = await sql`
        SELECT
          COUNT(*) as total,
          COALESCE(AVG(processing_time_ms), 0) as avg_time
        FROM email_verdicts
        WHERE created_at > NOW() - INTERVAL '24 hours'
      `;
      statsHour = await sql`
        SELECT COUNT(*) as total
        FROM email_verdicts
        WHERE created_at > NOW() - INTERVAL '1 hour'
      `;
    }

    return {
      processed24h: Number(stats24h[0]?.total) || 0,
      processedHour: Number(statsHour[0]?.total) || 0,
      queueDepth: 0, // Would come from queue system
      avgProcessingTime: Number(stats24h[0]?.avg_time) || 0,
    };
  } catch (error) {
    console.error('Failed to collect email metrics:', error);
    return {
      processed24h: 0,
      processedHour: 0,
      queueDepth: 0,
      avgProcessingTime: 0,
    };
  }
}

async function collectDetectionMetrics(tenantId?: string): Promise<DetectionMetrics> {
  try {
    let stats: Array<Record<string, unknown>>;

    if (tenantId) {
      stats = await sql`
        SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE verdict = 'block') as blocked,
          COUNT(*) FILTER (WHERE verdict = 'quarantine') as quarantined,
          COUNT(*) FILTER (WHERE action_taken = 'release' AND verdict IN ('block', 'quarantine')) as false_positives,
          COALESCE(AVG(confidence), 0) as avg_confidence
        FROM email_verdicts
        WHERE tenant_id = ${tenantId} AND created_at > NOW() - INTERVAL '24 hours'
      `;
    } else {
      stats = await sql`
        SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE verdict = 'block') as blocked,
          COUNT(*) FILTER (WHERE verdict = 'quarantine') as quarantined,
          COUNT(*) FILTER (WHERE action_taken = 'release' AND verdict IN ('block', 'quarantine')) as false_positives,
          COALESCE(AVG(confidence), 0) as avg_confidence
        FROM email_verdicts
        WHERE created_at > NOW() - INTERVAL '24 hours'
      `;
    }

    const row = stats[0] || {};
    return {
      threatsDetected24h: Number(row.total) || 0,
      threatsBlocked24h: Number(row.blocked) || 0,
      quarantined24h: Number(row.quarantined) || 0,
      falsePositives24h: Number(row.false_positives) || 0,
      avgConfidence: Number(row.avg_confidence) || 0,
    };
  } catch (error) {
    console.error('Failed to collect detection metrics:', error);
    return {
      threatsDetected24h: 0,
      threatsBlocked24h: 0,
      quarantined24h: 0,
      falsePositives24h: 0,
      avgConfidence: 0,
    };
  }
}

function collectPerformanceMetrics(): PerformanceMetrics {
  const times = [...metricsStore.responseTimes].sort((a, b) => a - b);
  const count = times.length || 1;

  return {
    avgResponseTime: times.reduce((a, b) => a + b, 0) / count,
    p95ResponseTime: times[Math.floor(count * 0.95)] || 0,
    p99ResponseTime: times[Math.floor(count * 0.99)] || 0,
    errorRate: metricsStore.errorCount / (metricsStore.requestCount || 1) * 100,
    requestsPerMinute: metricsStore.requestCount / ((Date.now() - metricsStore.lastReset) / 60000),
  };
}

async function collectIntegrationMetrics(tenantId?: string): Promise<IntegrationMetrics> {
  try {
    let googleStats: Array<Record<string, unknown>>;
    let msStats: Array<Record<string, unknown>>;

    if (tenantId) {
      googleStats = await sql`
        SELECT
          COUNT(*) FILTER (WHERE status = 'connected') as connected,
          COUNT(*) FILTER (WHERE status = 'pending') as syncing,
          COUNT(*) FILTER (WHERE status = 'error') as errored,
          MAX(last_sync_at) as last_sync
        FROM integrations
        WHERE tenant_id = ${tenantId} AND type = 'gmail'
      `;
      msStats = await sql`
        SELECT
          COUNT(*) FILTER (WHERE status = 'connected') as connected,
          COUNT(*) FILTER (WHERE status = 'pending') as syncing,
          COUNT(*) FILTER (WHERE status = 'error') as errored,
          MAX(last_sync_at) as last_sync
        FROM integrations
        WHERE tenant_id = ${tenantId} AND type = 'o365'
      `;
    } else {
      googleStats = await sql`
        SELECT
          COUNT(*) FILTER (WHERE status = 'connected') as connected,
          COUNT(*) FILTER (WHERE status = 'pending') as syncing,
          COUNT(*) FILTER (WHERE status = 'error') as errored,
          MAX(last_sync_at) as last_sync
        FROM integrations
        WHERE type = 'gmail'
      `;
      msStats = await sql`
        SELECT
          COUNT(*) FILTER (WHERE status = 'connected') as connected,
          COUNT(*) FILTER (WHERE status = 'pending') as syncing,
          COUNT(*) FILTER (WHERE status = 'error') as errored,
          MAX(last_sync_at) as last_sync
        FROM integrations
        WHERE type = 'o365'
      `;
    }

    const google = googleStats[0] || {};
    const ms = msStats[0] || {};

    return {
      googleWorkspace: {
        connected: Number(google.connected) || 0,
        syncing: Number(google.syncing) || 0,
        errored: Number(google.errored) || 0,
        lastSyncTime: google.last_sync ? new Date(google.last_sync as string) : undefined,
      },
      microsoft365: {
        connected: Number(ms.connected) || 0,
        syncing: Number(ms.syncing) || 0,
        errored: Number(ms.errored) || 0,
        lastSyncTime: ms.last_sync ? new Date(ms.last_sync as string) : undefined,
      },
      webhooksActive: 0, // Would come from webhooks table
      apiRequestsHour: 0, // Would come from request logs
    };
  } catch (error) {
    console.error('Failed to collect integration metrics:', error);
    return {
      googleWorkspace: { connected: 0, syncing: 0, errored: 0 },
      microsoft365: { connected: 0, syncing: 0, errored: 0 },
      webhooksActive: 0,
      apiRequestsHour: 0,
    };
  }
}

function determineHealthStatus(
  email: EmailMetrics,
  detection: DetectionMetrics
): 'healthy' | 'degraded' | 'unhealthy' {
  // Check for critical issues
  if (email.queueDepth > 1000) return 'unhealthy';
  if (email.avgProcessingTime > 30) return 'degraded';

  // High false positive rate indicates issues
  const fpRate = detection.falsePositives24h / (detection.threatsDetected24h || 1);
  if (fpRate > 0.2) return 'degraded';

  return 'healthy';
}

/**
 * Format metrics for Prometheus exposition
 */
export function formatPrometheusMetrics(metrics: SystemMetrics): string {
  const lines: string[] = [
    '# HELP swordfish_uptime_seconds System uptime in seconds',
    '# TYPE swordfish_uptime_seconds gauge',
    `swordfish_uptime_seconds ${metrics.system.uptime}`,
    '',
    '# HELP swordfish_emails_processed_total Total emails processed',
    '# TYPE swordfish_emails_processed_total counter',
    `swordfish_emails_processed_total{period="24h"} ${metrics.email.processed24h}`,
    `swordfish_emails_processed_total{period="1h"} ${metrics.email.processedHour}`,
    '',
    '# HELP swordfish_threats_detected_total Total threats detected',
    '# TYPE swordfish_threats_detected_total counter',
    `swordfish_threats_detected_total{period="24h"} ${metrics.detection.threatsDetected24h}`,
    '',
    '# HELP swordfish_threats_blocked_total Total threats blocked',
    '# TYPE swordfish_threats_blocked_total counter',
    `swordfish_threats_blocked_total{period="24h"} ${metrics.detection.threatsBlocked24h}`,
    '',
    '# HELP swordfish_response_time_seconds Response time in seconds',
    '# TYPE swordfish_response_time_seconds gauge',
    `swordfish_response_time_seconds{quantile="avg"} ${metrics.performance.avgResponseTime / 1000}`,
    `swordfish_response_time_seconds{quantile="p95"} ${metrics.performance.p95ResponseTime / 1000}`,
    `swordfish_response_time_seconds{quantile="p99"} ${metrics.performance.p99ResponseTime / 1000}`,
    '',
    '# HELP swordfish_error_rate Error rate percentage',
    '# TYPE swordfish_error_rate gauge',
    `swordfish_error_rate ${metrics.performance.errorRate}`,
    '',
    '# HELP swordfish_integrations_connected Total connected integrations',
    '# TYPE swordfish_integrations_connected gauge',
    `swordfish_integrations_connected{provider="google"} ${metrics.integrations.googleWorkspace.connected}`,
    `swordfish_integrations_connected{provider="microsoft"} ${metrics.integrations.microsoft365.connected}`,
  ];

  return lines.join('\n');
}
