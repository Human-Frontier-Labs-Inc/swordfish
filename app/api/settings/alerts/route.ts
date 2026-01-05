/**
 * Alert Configuration API
 *
 * Manage alert rules and view active alerts
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  createAlertRule,
  getAlertRules,
  updateAlertRule,
  deleteAlertRule,
  getActiveAlerts,
  acknowledgeAlert,
  resolveAlert,
  SYSTEM_ALERT_RULES,
} from '@/lib/monitoring/alerts';

/**
 * GET /api/settings/alerts
 *
 * Get alert rules and active alerts
 */
export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const { searchParams } = new URL(request.url);
    const type = searchParams.get('type') || 'rules';

    if (type === 'alerts') {
      const alerts = await getActiveAlerts(tenantId);
      return NextResponse.json({ alerts });
    }

    const rules = await getAlertRules(tenantId);
    return NextResponse.json({
      rules,
      systemRules: SYSTEM_ALERT_RULES,
    });
  } catch (error) {
    console.error('Alert API error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch alerts' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/settings/alerts
 *
 * Create a new alert rule
 */
export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const body = await request.json();

    const {
      name,
      description,
      condition,
      actions,
      isActive = true,
      cooldownMinutes = 60,
    } = body;

    // Validate required fields
    if (!name || !condition || !actions) {
      return NextResponse.json(
        { error: 'Missing required fields: name, condition, actions' },
        { status: 400 }
      );
    }

    // Validate condition structure
    if (!condition.type || !condition.metric || !condition.operator || condition.value === undefined) {
      return NextResponse.json(
        { error: 'Invalid condition structure' },
        { status: 400 }
      );
    }

    const rule = await createAlertRule(tenantId, {
      name,
      description: description || '',
      condition,
      actions,
      isActive,
      cooldownMinutes,
    });

    return NextResponse.json({ rule }, { status: 201 });
  } catch (error) {
    console.error('Create alert rule error:', error);
    return NextResponse.json(
      { error: 'Failed to create alert rule' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/settings/alerts
 *
 * Update an alert rule or alert status
 */
export async function PATCH(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const body = await request.json();

    const { action, ruleId, alertId, updates } = body;

    // Handle alert actions
    if (action === 'acknowledge' && alertId) {
      const success = await acknowledgeAlert(alertId, tenantId, userId);
      return NextResponse.json({ success });
    }

    if (action === 'resolve' && alertId) {
      const success = await resolveAlert(alertId, tenantId);
      return NextResponse.json({ success });
    }

    // Handle rule updates
    if (ruleId && updates) {
      const success = await updateAlertRule(ruleId, tenantId, updates);
      return NextResponse.json({ success });
    }

    return NextResponse.json(
      { error: 'Invalid request' },
      { status: 400 }
    );
  } catch (error) {
    console.error('Update alert error:', error);
    return NextResponse.json(
      { error: 'Failed to update' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/settings/alerts
 *
 * Delete an alert rule
 */
export async function DELETE(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const { searchParams } = new URL(request.url);
    const ruleId = searchParams.get('ruleId');

    if (!ruleId) {
      return NextResponse.json(
        { error: 'Missing ruleId parameter' },
        { status: 400 }
      );
    }

    const success = await deleteAlertRule(ruleId, tenantId);
    return NextResponse.json({ success });
  } catch (error) {
    console.error('Delete alert rule error:', error);
    return NextResponse.json(
      { error: 'Failed to delete alert rule' },
      { status: 500 }
    );
  }
}
