/**
 * Metrics Endpoint
 *
 * Expose system metrics for monitoring (Prometheus, Datadog, etc.)
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { collectMetrics, formatPrometheusMetrics } from '@/lib/monitoring/metrics';
import { getTenantId } from '@/lib/auth/tenant';

/**
 * GET /api/metrics
 *
 * Returns system metrics in JSON or Prometheus format
 */
export async function GET(request: NextRequest) {
  try {
    const { userId } = await auth();

    // Allow unauthenticated access for monitoring systems with token
    const authToken = request.headers.get('Authorization');
    const metricsToken = process.env.METRICS_AUTH_TOKEN;
    const isTokenAuth = metricsToken && authToken === `Bearer ${metricsToken}`;

    if (!userId && !isTokenAuth) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Get tenant-specific metrics if authenticated user, otherwise system-wide for token auth
    let tenantId: string | undefined;
    if (userId) {
      try {
        tenantId = await getTenantId();
      } catch {
        // If getTenantId fails but we have token auth, fall through to system-wide
        if (!isTokenAuth) {
          return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
        }
      }
    }

    // Collect metrics
    const metrics = await collectMetrics(tenantId);

    // Check Accept header for format
    const acceptHeader = request.headers.get('Accept') || '';

    if (acceptHeader.includes('text/plain') || acceptHeader.includes('text/prometheus')) {
      // Return Prometheus exposition format
      const prometheusMetrics = formatPrometheusMetrics(metrics);
      return new NextResponse(prometheusMetrics, {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
        },
      });
    }

    // Return JSON format
    return NextResponse.json(metrics);
  } catch (error) {
    console.error('Metrics endpoint error:', error);
    return NextResponse.json(
      { error: 'Failed to collect metrics' },
      { status: 500 }
    );
  }
}
