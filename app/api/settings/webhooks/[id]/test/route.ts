/**
 * Webhook Test API
 * POST - Send test event to webhook
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import crypto from 'crypto';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;
    const tenantId = orgId || `personal_${userId}`;

    // Get webhook
    const webhooks = await sql`
      SELECT url, secret FROM webhooks
      WHERE id = ${id}::uuid AND tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (webhooks.length === 0) {
      return NextResponse.json({ error: 'Webhook not found' }, { status: 404 });
    }

    const webhook = webhooks[0];

    // Create test payload
    const testPayload = {
      event: 'test',
      timestamp: new Date().toISOString(),
      data: {
        message: 'This is a test webhook from Swordfish',
        tenant_id: tenantId,
      },
    };

    const payloadString = JSON.stringify(testPayload);

    // Create signature
    const signature = crypto
      .createHmac('sha256', webhook.secret as string)
      .update(payloadString)
      .digest('hex');

    // Send test request
    const startTime = Date.now();
    let responseStatus: number;
    let responseTime: number;

    try {
      const response = await fetch(webhook.url as string, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Swordfish-Signature': signature,
          'X-Swordfish-Event': 'test',
          'X-Swordfish-Timestamp': testPayload.timestamp,
        },
        body: payloadString,
      });

      responseTime = Date.now() - startTime;
      responseStatus = response.status;

      // Update webhook status
      await sql`
        UPDATE webhooks SET
          last_triggered_at = NOW(),
          last_status = ${response.ok ? 'success' : 'failed'},
          failure_count = CASE WHEN ${response.ok} THEN 0 ELSE failure_count + 1 END,
          updated_at = NOW()
        WHERE id = ${id}::uuid
      `;

      if (!response.ok) {
        return NextResponse.json({
          success: false,
          error: `Webhook returned status ${response.status}`,
          responseTime,
        });
      }

      return NextResponse.json({
        success: true,
        responseTime,
        status: responseStatus,
      });
    } catch (fetchError) {
      responseTime = Date.now() - startTime;

      // Update webhook failure
      await sql`
        UPDATE webhooks SET
          last_triggered_at = NOW(),
          last_status = 'failed',
          failure_count = failure_count + 1,
          updated_at = NOW()
        WHERE id = ${id}::uuid
      `;

      return NextResponse.json({
        success: false,
        error: 'Failed to reach webhook endpoint',
        responseTime,
      });
    }
  } catch (error) {
    console.error('Test webhook error:', error);
    return NextResponse.json(
      { error: 'Failed to test webhook' },
      { status: 500 }
    );
  }
}
