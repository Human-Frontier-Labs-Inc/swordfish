/**
 * Legacy Nango Sync Endpoint (DEPRECATED)
 *
 * This endpoint existed for syncing with Nango.
 * Nango has been replaced with direct OAuth token management.
 * This stub exists only to prevent 405 errors from legacy frontend code.
 */

import { NextResponse } from 'next/server';

export async function POST() {
  return NextResponse.json({
    deprecated: true,
    message: 'Nango integration has been replaced with direct OAuth. Please reconnect your integrations.',
  });
}

export async function GET() {
  return NextResponse.json({
    deprecated: true,
    message: 'Nango integration has been replaced with direct OAuth. Please reconnect your integrations.',
  });
}
