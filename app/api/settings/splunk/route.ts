/**
 * Splunk Integration Settings API
 *
 * GET /api/settings/splunk - Get Splunk config
 * POST /api/settings/splunk - Create/Update Splunk config
 * DELETE /api/settings/splunk - Remove Splunk config
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { nanoid } from 'nanoid';
import { testSplunkConnection, SplunkConfig } from '@/lib/integrations/splunk';

const VALID_EVENT_TYPES = ['threat', 'policy', 'quarantine', 'integration'];

// GET /api/settings/splunk
export async function GET() {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;

    const result = await sql`
      SELECT id, name, hec_url, index_name, source_name, source_type, is_active, event_types, created_at, updated_at
      FROM splunk_integrations
      WHERE tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (result.length === 0) {
      return NextResponse.json({
        configured: false,
        splunk: null,
        availableEventTypes: VALID_EVENT_TYPES,
      });
    }

    const s = result[0];

    // Get delivery stats
    const stats = await sql`
      SELECT
        COUNT(*)::int as total,
        COUNT(*) FILTER (WHERE success = true)::int as successful,
        MAX(created_at) as last_delivery
      FROM splunk_deliveries
      WHERE integration_id = ${s.id}
        AND created_at > NOW() - INTERVAL '7 days'
    `;

    const stat = stats[0] || { total: 0, successful: 0, last_delivery: null };

    return NextResponse.json({
      configured: true,
      splunk: {
        id: s.id,
        name: s.name,
        hecUrl: s.hec_url,
        index: s.index_name,
        source: s.source_name,
        sourceType: s.source_type,
        isActive: s.is_active,
        eventTypes: s.event_types,
        createdAt: s.created_at,
        updatedAt: s.updated_at,
        stats: {
          totalDeliveries: stat.total,
          successfulDeliveries: stat.successful,
          successRate: stat.total > 0 ? (stat.successful / stat.total) * 100 : 100,
          lastDelivery: stat.last_delivery,
        },
      },
      availableEventTypes: VALID_EVENT_TYPES,
    });
  } catch (error) {
    console.error('Failed to get Splunk config:', error);
    return NextResponse.json(
      { error: 'Failed to get Splunk configuration' },
      { status: 500 }
    );
  }
}

// POST /api/settings/splunk
export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const body = await request.json();
    const {
      name = 'Splunk HEC',
      hecUrl,
      hecToken,
      index = 'main',
      source = 'swordfish',
      sourceType = 'cef',
      eventTypes = ['threat', 'quarantine'],
      testConnection = true,
    } = body;

    // Validation
    if (!hecUrl || typeof hecUrl !== 'string') {
      return NextResponse.json({ error: 'hecUrl is required' }, { status: 400 });
    }

    if (!hecToken || typeof hecToken !== 'string') {
      return NextResponse.json({ error: 'hecToken is required' }, { status: 400 });
    }

    try {
      new URL(hecUrl);
    } catch {
      return NextResponse.json({ error: 'hecUrl must be a valid URL' }, { status: 400 });
    }

    if (!Array.isArray(eventTypes) || eventTypes.length === 0) {
      return NextResponse.json({ error: 'eventTypes must be a non-empty array' }, { status: 400 });
    }

    const invalidTypes = eventTypes.filter((t: string) => !VALID_EVENT_TYPES.includes(t));
    if (invalidTypes.length > 0) {
      return NextResponse.json({ error: `Invalid event types: ${invalidTypes.join(', ')}` }, { status: 400 });
    }

    // Test connection if requested
    if (testConnection) {
      const testConfig: SplunkConfig = {
        id: 'test',
        tenantId,
        name,
        hecUrl,
        hecToken,
        index,
        source,
        sourceType,
        isActive: true,
        eventTypes,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const testResult = await testSplunkConnection(testConfig);
      if (!testResult.success) {
        return NextResponse.json({
          error: 'Failed to connect to Splunk',
          details: testResult.error,
        }, { status: 400 });
      }
    }

    // Check for existing config
    const existing = await sql`
      SELECT id FROM splunk_integrations WHERE tenant_id = ${tenantId} LIMIT 1
    `;

    let splunkId: string;

    if (existing.length > 0) {
      // Update existing
      splunkId = existing[0].id as string;
      await sql`
        UPDATE splunk_integrations SET
          name = ${name},
          hec_url = ${hecUrl},
          hec_token = ${hecToken},
          index_name = ${index},
          source_name = ${source},
          source_type = ${sourceType},
          event_types = ${eventTypes},
          is_active = true,
          updated_at = NOW()
        WHERE id = ${splunkId}
      `;
    } else {
      // Create new
      splunkId = nanoid();
      await sql`
        INSERT INTO splunk_integrations (
          id, tenant_id, name, hec_url, hec_token, index_name, source_name, source_type, event_types, is_active, created_at, updated_at
        )
        VALUES (
          ${splunkId},
          ${tenantId},
          ${name},
          ${hecUrl},
          ${hecToken},
          ${index},
          ${source},
          ${sourceType},
          ${eventTypes},
          true,
          NOW(),
          NOW()
        )
      `;
    }

    // Log creation/update
    await sql`
      INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, resource_id, after_state, created_at)
      VALUES (
        ${nanoid()},
        ${tenantId},
        ${userId},
        ${existing.length > 0 ? 'splunk.updated' : 'splunk.created'},
        'splunk_integration',
        ${splunkId},
        ${JSON.stringify({ name, hecUrl, index, source, sourceType, eventTypes })},
        NOW()
      )
    `;

    return NextResponse.json({
      splunk: {
        id: splunkId,
        name,
        hecUrl,
        index,
        source,
        sourceType,
        eventTypes,
        isActive: true,
      },
      message: existing.length > 0 ? 'Splunk integration updated' : 'Splunk integration created',
    }, { status: existing.length > 0 ? 200 : 201 });
  } catch (error) {
    console.error('Failed to save Splunk config:', error);
    return NextResponse.json(
      { error: 'Failed to save Splunk configuration' },
      { status: 500 }
    );
  }
}

// DELETE /api/settings/splunk
export async function DELETE() {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;

    const deleted = await sql`
      DELETE FROM splunk_integrations
      WHERE tenant_id = ${tenantId}
      RETURNING id
    `;

    if (deleted.length === 0) {
      return NextResponse.json({ error: 'No Splunk integration found' }, { status: 404 });
    }

    // Log deletion
    await sql`
      INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, resource_id, created_at)
      VALUES (
        ${nanoid()},
        ${tenantId},
        ${userId},
        'splunk.deleted',
        'splunk_integration',
        ${deleted[0].id},
        NOW()
      )
    `;

    return NextResponse.json({ deleted: true });
  } catch (error) {
    console.error('Failed to delete Splunk config:', error);
    return NextResponse.json(
      { error: 'Failed to delete Splunk configuration' },
      { status: 500 }
    );
  }
}
