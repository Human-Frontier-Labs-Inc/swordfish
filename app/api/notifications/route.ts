/**
 * Notifications API
 * GET - List notifications
 * PATCH - Mark notifications as read
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  getNotifications,
  markNotificationsRead,
  getUnreadCount,
} from '@/lib/notifications/service';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const unreadOnly = searchParams.get('unread') === 'true';
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');
    const countOnly = searchParams.get('count') === 'true';

    if (countOnly) {
      const count = await getUnreadCount(tenantId);
      return NextResponse.json({ unreadCount: count });
    }

    const notifications = await getNotifications(tenantId, {
      unreadOnly,
      limit,
      offset,
    });

    const unreadCount = await getUnreadCount(tenantId);

    return NextResponse.json({
      notifications,
      unreadCount,
      pagination: {
        limit,
        offset,
        hasMore: notifications.length === limit,
      },
    });
  } catch (error) {
    console.error('List notifications error:', error);
    return NextResponse.json(
      { error: 'Failed to list notifications' },
      { status: 500 }
    );
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body = await request.json();

    const { notificationIds, markAllRead } = body;

    if (markAllRead) {
      // Get all unread notification IDs
      const notifications = await getNotifications(tenantId, { unreadOnly: true, limit: 1000 });
      const allIds = notifications.map((n) => n.id);
      await markNotificationsRead(tenantId, allIds);
    } else if (notificationIds && notificationIds.length > 0) {
      await markNotificationsRead(tenantId, notificationIds);
    } else {
      return NextResponse.json(
        { error: 'notificationIds or markAllRead is required' },
        { status: 400 }
      );
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Mark notifications read error:', error);
    return NextResponse.json(
      { error: 'Failed to mark notifications' },
      { status: 500 }
    );
  }
}
