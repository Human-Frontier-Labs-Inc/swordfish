/**
 * Bulk List Operations API
 * POST - Add multiple entries
 * DELETE - Remove multiple entries
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

interface BulkAddRequest {
  listType: 'allowlist' | 'blocklist';
  entryType: 'email' | 'domain' | 'ip' | 'url';
  values: string[];
  reason?: string;
  expiresAt?: string;
}

interface BulkDeleteRequest {
  ids: string[];
}

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body: BulkAddRequest = await request.json();

    const { listType, entryType, values, reason, expiresAt } = body;

    if (!listType || !entryType || !values || values.length === 0) {
      return NextResponse.json(
        { error: 'listType, entryType, and values are required' },
        { status: 400 }
      );
    }

    if (values.length > 1000) {
      return NextResponse.json(
        { error: 'Maximum 1000 entries per request' },
        { status: 400 }
      );
    }

    let addedCount = 0;
    const errors: string[] = [];

    for (const value of values) {
      try {
        const normalizedValue = value.toLowerCase().trim();
        if (!normalizedValue) continue;

        await sql`
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
          DO NOTHING
        `;
        addedCount++;
      } catch (error) {
        errors.push(`${value}: ${error instanceof Error ? error.message : 'Failed'}`);
      }
    }

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: `list.${listType}.bulk_add`,
      resourceType: 'list_entry',
      resourceId: 'bulk',
      afterState: {
        entryType,
        count: addedCount,
        errors: errors.length,
      },
    });

    return NextResponse.json({
      success: true,
      added: addedCount,
      errors: errors.length > 0 ? errors.slice(0, 10) : undefined,
    });
  } catch (error) {
    console.error('Bulk add error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to add entries' },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body: BulkDeleteRequest = await request.json();

    const { ids } = body;

    if (!ids || ids.length === 0) {
      return NextResponse.json(
        { error: 'ids array is required' },
        { status: 400 }
      );
    }

    if (ids.length > 1000) {
      return NextResponse.json(
        { error: 'Maximum 1000 entries per request' },
        { status: 400 }
      );
    }

    let deletedCount = 0;

    for (const id of ids) {
      try {
        const result = await sql`
          DELETE FROM list_entries
          WHERE id = ${id}
          AND tenant_id = ${tenantId}
          RETURNING id
        `;
        if (result.length > 0) {
          deletedCount++;
        }
      } catch (error) {
        // Continue on individual errors
      }
    }

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'list.bulk_delete',
      resourceType: 'list_entry',
      resourceId: 'bulk',
      afterState: { count: deletedCount },
    });

    return NextResponse.json({
      success: true,
      deleted: deletedCount,
    });
  } catch (error) {
    console.error('Bulk delete error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to delete entries' },
      { status: 500 }
    );
  }
}
