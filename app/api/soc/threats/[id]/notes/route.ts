/**
 * SOC Investigation Notes API
 *
 * Add investigation notes to threats
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth, currentUser } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { nanoid } from 'nanoid';
import { getTenantId, Unauthorized } from '@/lib/auth/tenant';

interface NoteBody {
  content: string;
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    let tenantId: string;
    try {
      tenantId = await getTenantId();
    } catch (e) {
      if (e instanceof Unauthorized) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }
      throw e;
    }

    const { id: threatId } = await params;
    const body: NoteBody = await request.json();

    if (!body.content?.trim()) {
      return NextResponse.json({ error: 'Note content is required' }, { status: 400 });
    }

    // Verify threat exists
    const threats = await sql`
      SELECT id FROM threats
      WHERE id = ${threatId} AND tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (threats.length === 0) {
      return NextResponse.json({ error: 'Threat not found' }, { status: 404 });
    }

    // Get user info for audit trail
    const { userId } = await auth();
    const user = await currentUser();
    const authorName = user?.fullName || user?.emailAddresses?.[0]?.emailAddress || 'Unknown';

    // Create note
    const noteId = nanoid();
    await sql`
      INSERT INTO investigation_notes (id, threat_id, tenant_id, author, author_id, content, created_at)
      VALUES (${noteId}, ${threatId}, ${tenantId}, ${authorName}, ${userId}, ${body.content.trim()}, NOW())
    `;

    return NextResponse.json({
      success: true,
      note: {
        id: noteId,
        author: authorName,
        content: body.content.trim(),
        createdAt: new Date(),
      },
    });
  } catch (error) {
    console.error('SOC note error:', error);
    return NextResponse.json(
      { error: 'Failed to add note' },
      { status: 500 }
    );
  }
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    let tenantId: string;
    try {
      tenantId = await getTenantId();
    } catch (e) {
      if (e instanceof Unauthorized) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }
      throw e;
    }

    const { id: threatId } = await params;

    const notes = await sql`
      SELECT id, author, content, created_at
      FROM investigation_notes
      WHERE threat_id = ${threatId} AND tenant_id = ${tenantId}
      ORDER BY created_at DESC
    `;

    return NextResponse.json({
      notes: notes.map((n: Record<string, unknown>) => ({
        id: n.id,
        author: n.author,
        content: n.content,
        createdAt: n.created_at,
      })),
    });
  } catch (error) {
    console.error('SOC notes fetch error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch notes' },
      { status: 500 }
    );
  }
}
