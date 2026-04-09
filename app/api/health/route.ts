/**
 * Health Check Endpoint
 *
 * Public endpoint (no auth required) for monitoring and load balancers.
 * Checks database connectivity and returns health status.
 */

import { NextResponse } from 'next/server';
import { sql } from '@/lib/db';

export interface HealthResponse {
  status: 'healthy' | 'unhealthy';
  database: 'connected' | 'disconnected';
  timestamp: string;
  error?: string;
}

export async function GET(): Promise<NextResponse<HealthResponse>> {
  try {
    await sql`SELECT 1 AS health_check`;

    return NextResponse.json({
      status: 'healthy',
      database: 'connected',
      timestamp: new Date().toISOString(),
    }, { status: 200 });
  } catch (error) {
    return NextResponse.json({
      status: 'unhealthy',
      database: 'disconnected',
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Database connection failed',
    }, { status: 503 });
  }
}

/**
 * Liveness probe - simple check if the service is running
 */
export async function HEAD(): Promise<NextResponse> {
  return new NextResponse(null, { status: 200 });
}
