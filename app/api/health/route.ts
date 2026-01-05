/**
 * Health Check Endpoint
 *
 * Production health checks for monitoring and load balancers
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  checks: HealthCheck[];
}

export interface HealthCheck {
  name: string;
  status: 'pass' | 'warn' | 'fail';
  latency?: number;
  message?: string;
}

export async function GET(request: NextRequest) {
  const startTime = Date.now();
  const checks: HealthCheck[] = [];

  // Check database connectivity
  const dbCheck = await checkDatabase();
  checks.push(dbCheck);

  // Check external dependencies
  const depsCheck = await checkDependencies();
  checks.push(depsCheck);

  // Check memory usage
  const memoryCheck = checkMemoryUsage();
  checks.push(memoryCheck);

  // Determine overall status
  const hasFailure = checks.some((c) => c.status === 'fail');
  const hasWarning = checks.some((c) => c.status === 'warn');

  const status: HealthStatus['status'] = hasFailure
    ? 'unhealthy'
    : hasWarning
    ? 'degraded'
    : 'healthy';

  const response: HealthStatus = {
    status,
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    checks,
  };

  // Return appropriate HTTP status code
  const httpStatus = status === 'healthy' ? 200 : status === 'degraded' ? 200 : 503;

  return NextResponse.json(response, { status: httpStatus });
}

async function checkDatabase(): Promise<HealthCheck> {
  const startTime = Date.now();

  try {
    // Simple query to verify database connectivity
    await sql`SELECT 1 as health_check`;

    return {
      name: 'database',
      status: 'pass',
      latency: Date.now() - startTime,
      message: 'Database connection successful',
    };
  } catch (error) {
    return {
      name: 'database',
      status: 'fail',
      latency: Date.now() - startTime,
      message: error instanceof Error ? error.message : 'Database connection failed',
    };
  }
}

async function checkDependencies(): Promise<HealthCheck> {
  const startTime = Date.now();
  const issues: string[] = [];

  // Check if required environment variables are set
  const requiredEnvVars = [
    'DATABASE_URL',
    'CLERK_SECRET_KEY',
    'NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY',
  ];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      issues.push(`Missing ${envVar}`);
    }
  }

  if (issues.length > 0) {
    return {
      name: 'dependencies',
      status: 'warn',
      latency: Date.now() - startTime,
      message: issues.join(', '),
    };
  }

  return {
    name: 'dependencies',
    status: 'pass',
    latency: Date.now() - startTime,
    message: 'All dependencies configured',
  };
}

function checkMemoryUsage(): HealthCheck {
  const usage = process.memoryUsage();
  const heapUsedMB = Math.round(usage.heapUsed / 1024 / 1024);
  const heapTotalMB = Math.round(usage.heapTotal / 1024 / 1024);
  const heapPercent = (usage.heapUsed / usage.heapTotal) * 100;

  let status: HealthCheck['status'] = 'pass';
  let message = `Heap: ${heapUsedMB}MB / ${heapTotalMB}MB (${heapPercent.toFixed(1)}%)`;

  if (heapPercent > 90) {
    status = 'fail';
    message = `Memory critical: ${message}`;
  } else if (heapPercent > 75) {
    status = 'warn';
    message = `Memory warning: ${message}`;
  }

  return {
    name: 'memory',
    status,
    message,
  };
}

/**
 * Liveness probe - simple check if the service is running
 */
export async function HEAD() {
  return new NextResponse(null, { status: 200 });
}
