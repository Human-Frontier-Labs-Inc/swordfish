/**
 * Notification Config API
 * GET - Get notification configs
 * POST - Create/update notification config
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  getNotificationConfigs,
  upsertNotificationConfig,
  type NotificationChannel,
  type NotificationType,
} from '@/lib/notifications/service';
import { logAuditEvent } from '@/lib/db/audit';

export async function GET() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const configs = await getNotificationConfigs(tenantId);

    return NextResponse.json({ configs });
  } catch (error) {
    console.error('Get notification configs error:', error);
    return NextResponse.json(
      { error: 'Failed to get configs' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body = await request.json();

    const { channel, enabled, types, destination, minSeverity } = body;

    if (!channel || !destination) {
      return NextResponse.json(
        { error: 'channel and destination are required' },
        { status: 400 }
      );
    }

    const validChannels: NotificationChannel[] = ['email', 'slack', 'webhook', 'in_app'];
    if (!validChannels.includes(channel)) {
      return NextResponse.json(
        { error: 'Invalid channel' },
        { status: 400 }
      );
    }

    const validTypes: NotificationType[] = [
      'threat_detected',
      'threat_quarantined',
      'threat_released',
      'policy_violation',
      'integration_error',
      'daily_summary',
      'weekly_report',
    ];

    const filteredTypes = (types || []).filter((t: NotificationType) => validTypes.includes(t));

    const id = await upsertNotificationConfig({
      tenantId,
      channel,
      enabled: enabled !== false,
      types: filteredTypes,
      destination,
      minSeverity: minSeverity || 'warning',
    });

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'notification_config.update',
      resourceType: 'notification_config',
      resourceId: id,
      afterState: { channel, enabled },
    });

    return NextResponse.json({ success: true, id });
  } catch (error) {
    console.error('Update notification config error:', error);
    return NextResponse.json(
      { error: 'Failed to update config' },
      { status: 500 }
    );
  }
}
