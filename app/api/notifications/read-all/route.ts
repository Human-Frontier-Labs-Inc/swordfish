/**
 * Mark All Notifications Read API
 * POST - Mark all notifications as read
 */

import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function POST() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    await sql`
      UPDATE notifications
      SET read = true, read_at = NOW()
      WHERE tenant_id = ${tenantId} AND read = false
    `;

    return NextResponse.json({
      success: true,
    });
  } catch (error) {
    console.error('Mark all notifications read error:', error);
    return NextResponse.json(
      { error: 'Failed to mark all notifications as read' },
      { status: 500 }
    );
  }
}
