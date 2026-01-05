/**
 * VIP List Management API
 * CRUD operations for VIP/Executive list
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  getVIPList,
  addVIP,
  updateVIP,
  removeVIP,
  bulkImportVIPs,
  getVIPStats,
  type VIPRole,
} from '@/lib/detection/bec/vip-list';

/**
 * GET /api/settings/vip
 * Get all VIPs for the tenant
 */
export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const searchParams = request.nextUrl.searchParams;
    const includeStats = searchParams.get('stats') === 'true';

    const vips = await getVIPList(tenantId);

    if (includeStats) {
      const stats = await getVIPStats(tenantId);
      return NextResponse.json({
        vips,
        stats,
      });
    }

    return NextResponse.json({ vips });
  } catch (error) {
    console.error('Failed to get VIP list:', error);
    return NextResponse.json(
      { error: 'Failed to retrieve VIP list' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/settings/vip
 * Add a new VIP
 */
export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const body = await request.json();

    // Validate required fields
    if (!body.email || !body.displayName || !body.role) {
      return NextResponse.json(
        { error: 'Missing required fields: email, displayName, role' },
        { status: 400 }
      );
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(body.email)) {
      return NextResponse.json(
        { error: 'Invalid email format' },
        { status: 400 }
      );
    }

    // Validate role
    const validRoles: VIPRole[] = ['executive', 'finance', 'hr', 'it', 'legal', 'board', 'assistant', 'custom'];
    if (!validRoles.includes(body.role)) {
      return NextResponse.json(
        { error: `Invalid role. Must be one of: ${validRoles.join(', ')}` },
        { status: 400 }
      );
    }

    const vip = await addVIP(tenantId, {
      email: body.email,
      displayName: body.displayName,
      title: body.title,
      department: body.department,
      role: body.role,
      aliases: body.aliases || [],
    });

    return NextResponse.json({ vip }, { status: 201 });
  } catch (error) {
    console.error('Failed to add VIP:', error);
    return NextResponse.json(
      { error: 'Failed to add VIP' },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/settings/vip
 * Update an existing VIP
 */
export async function PUT(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const body = await request.json();

    if (!body.id) {
      return NextResponse.json(
        { error: 'Missing required field: id' },
        { status: 400 }
      );
    }

    // Validate email format if provided
    if (body.email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(body.email)) {
        return NextResponse.json(
          { error: 'Invalid email format' },
          { status: 400 }
        );
      }
    }

    // Validate role if provided
    if (body.role) {
      const validRoles: VIPRole[] = ['executive', 'finance', 'hr', 'it', 'legal', 'board', 'assistant', 'custom'];
      if (!validRoles.includes(body.role)) {
        return NextResponse.json(
          { error: `Invalid role. Must be one of: ${validRoles.join(', ')}` },
          { status: 400 }
        );
      }
    }

    await updateVIP(tenantId, body.id, {
      email: body.email,
      displayName: body.displayName,
      title: body.title,
      department: body.department,
      role: body.role,
      aliases: body.aliases,
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Failed to update VIP:', error);
    return NextResponse.json(
      { error: 'Failed to update VIP' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/settings/vip
 * Remove a VIP
 */
export async function DELETE(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const searchParams = request.nextUrl.searchParams;
    const id = searchParams.get('id');

    if (!id) {
      return NextResponse.json(
        { error: 'Missing required parameter: id' },
        { status: 400 }
      );
    }

    await removeVIP(tenantId, id);

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Failed to remove VIP:', error);
    return NextResponse.json(
      { error: 'Failed to remove VIP' },
      { status: 500 }
    );
  }
}
