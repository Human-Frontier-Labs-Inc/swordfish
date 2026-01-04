/**
 * Lists API (Allowlists/Blocklists)
 * GET - List entries
 * POST - Add entry
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const listType = searchParams.get('type') || 'all'; // 'allowlist', 'blocklist', 'all'
    const entryType = searchParams.get('entryType'); // 'email', 'domain', 'ip', 'url'

    let entries;

    if (listType === 'all') {
      if (entryType) {
        entries = await sql`
          SELECT * FROM list_entries
          WHERE tenant_id = ${tenantId}
          AND entry_type = ${entryType}
          ORDER BY created_at DESC
        `;
      } else {
        entries = await sql`
          SELECT * FROM list_entries
          WHERE tenant_id = ${tenantId}
          ORDER BY created_at DESC
        `;
      }
    } else {
      if (entryType) {
        entries = await sql`
          SELECT * FROM list_entries
          WHERE tenant_id = ${tenantId}
          AND list_type = ${listType}
          AND entry_type = ${entryType}
          ORDER BY created_at DESC
        `;
      } else {
        entries = await sql`
          SELECT * FROM list_entries
          WHERE tenant_id = ${tenantId}
          AND list_type = ${listType}
          ORDER BY created_at DESC
        `;
      }
    }

    const formatted = entries.map((e: Record<string, unknown>) => ({
      id: e.id,
      listType: e.list_type,
      entryType: e.entry_type,
      value: e.value,
      reason: e.reason,
      expiresAt: e.expires_at,
      createdAt: e.created_at,
      createdBy: e.created_by,
    }));

    return NextResponse.json({ entries: formatted });
  } catch (error) {
    console.error('List entries error:', error);
    return NextResponse.json({ entries: [] });
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

    const { listType, entryType, value, reason, expiresAt } = body;

    if (!listType || !entryType || !value) {
      return NextResponse.json(
        { error: 'listType, entryType, and value are required' },
        { status: 400 }
      );
    }

    if (!['allowlist', 'blocklist'].includes(listType)) {
      return NextResponse.json(
        { error: 'listType must be "allowlist" or "blocklist"' },
        { status: 400 }
      );
    }

    if (!['email', 'domain', 'ip', 'url'].includes(entryType)) {
      return NextResponse.json(
        { error: 'entryType must be "email", "domain", "ip", or "url"' },
        { status: 400 }
      );
    }

    // Validate value format based on type
    const normalizedValue = value.toLowerCase().trim();

    if (entryType === 'email' && !normalizedValue.includes('@')) {
      return NextResponse.json({ error: 'Invalid email format' }, { status: 400 });
    }

    if (entryType === 'ip') {
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
      if (!ipRegex.test(normalizedValue)) {
        return NextResponse.json({ error: 'Invalid IP address format' }, { status: 400 });
      }
    }

    const result = await sql`
      INSERT INTO list_entries (
        tenant_id, list_type, entry_type, value, reason, expires_at, created_by
      ) VALUES (
        ${tenantId},
        ${listType},
        ${entryType},
        ${normalizedValue},
        ${reason || null},
        ${expiresAt || null},
        ${userId}
      )
      ON CONFLICT (tenant_id, list_type, entry_type, value)
      DO UPDATE SET
        reason = COALESCE(${reason || null}, list_entries.reason),
        expires_at = COALESCE(${expiresAt || null}, list_entries.expires_at)
      RETURNING id
    `;

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: `list.${listType}.add`,
      resourceType: 'list_entry',
      resourceId: result[0].id as string,
      afterState: { entryType, value: normalizedValue },
    });

    return NextResponse.json({
      success: true,
      id: result[0].id,
    });
  } catch (error) {
    console.error('Add list entry error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to add entry' },
      { status: 500 }
    );
  }
}
