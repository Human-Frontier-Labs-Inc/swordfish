/**
 * SOC Threat Action API
 *
 * Execute actions on threats (release, delete, block sender)
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

interface ActionBody {
  action: 'release' | 'delete' | 'block_sender';
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id: threatId } = await params;
    const tenantId = orgId || userId;
    const body: ActionBody = await request.json();

    // Verify threat exists and belongs to tenant
    const threats = await sql`
      SELECT id, from_address, verdict
      FROM threats
      WHERE id = ${threatId} AND tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (threats.length === 0) {
      return NextResponse.json({ error: 'Threat not found' }, { status: 404 });
    }

    const threat = threats[0];

    switch (body.action) {
      case 'release':
        await sql`
          UPDATE threats
          SET
            action_taken = 'released',
            action_taken_at = NOW(),
            action_taken_by = ${userId}
          WHERE id = ${threatId}
        `;

        // Log the action
        await logAction(threatId, tenantId, userId, 'release', 'Threat released by analyst');
        break;

      case 'delete':
        await sql`
          UPDATE threats
          SET
            action_taken = 'deleted',
            action_taken_at = NOW(),
            action_taken_by = ${userId}
          WHERE id = ${threatId}
        `;

        await logAction(threatId, tenantId, userId, 'delete', 'Threat deleted by analyst');
        break;

      case 'block_sender':
        // Add sender to blocklist
        await sql`
          INSERT INTO sender_blocklist (tenant_id, email, reason, blocked_by, blocked_at)
          VALUES (${tenantId}, ${threat.from_address}, 'Blocked via SOC investigation', ${userId}, NOW())
          ON CONFLICT (tenant_id, email) DO UPDATE SET
            reason = EXCLUDED.reason,
            blocked_by = EXCLUDED.blocked_by,
            blocked_at = EXCLUDED.blocked_at
        `;

        await logAction(threatId, tenantId, userId, 'block_sender', `Sender ${threat.from_address} blocked`);
        break;

      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
    }

    return NextResponse.json({
      success: true,
      action: body.action,
      threatId,
    });
  } catch (error) {
    console.error('SOC action error:', error);
    return NextResponse.json(
      { error: 'Action failed' },
      { status: 500 }
    );
  }
}

async function logAction(
  threatId: string,
  tenantId: string,
  userId: string,
  action: string,
  details: string
) {
  try {
    await sql`
      INSERT INTO audit_log (tenant_id, user_id, action, resource_type, resource_id, details, created_at)
      VALUES (${tenantId}, ${userId}, ${action}, 'threat', ${threatId}, ${details}, NOW())
    `;
  } catch (error) {
    console.error('Failed to log action:', error);
  }
}
