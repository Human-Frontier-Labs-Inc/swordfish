/**
 * Feedback API
 * GET - List all feedback for the tenant
 * POST - Submit feedback for a message by message_id
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

type FeedbackType = 'false_positive' | 'false_negative' | 'confirmed_threat' | 'spam' | 'phishing' | 'malware' | 'other';

/**
 * GET - List feedback with pagination and filters
 */
export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const limit = Math.min(parseInt(searchParams.get('limit') || '20'), 100);
    const type = searchParams.get('type');
    const offset = (page - 1) * limit;

    // Build query with optional type filter
    let feedback;
    let total;

    if (type) {
      feedback = await sql`
        SELECT
          f.id,
          f.threat_id,
          f.message_id,
          f.feedback_type,
          f.notes,
          f.original_verdict,
          f.original_score,
          f.corrected_verdict,
          f.user_email,
          f.created_at,
          t.subject,
          t.sender_email,
          t.status as threat_status
        FROM feedback f
        LEFT JOIN threats t ON f.threat_id = t.id
        WHERE f.tenant_id = ${tenantId}
        AND f.feedback_type = ${type}
        ORDER BY f.created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      const countResult = await sql`
        SELECT COUNT(*)::int as count
        FROM feedback
        WHERE tenant_id = ${tenantId}
        AND feedback_type = ${type}
      `;
      total = countResult[0]?.count || 0;
    } else {
      feedback = await sql`
        SELECT
          f.id,
          f.threat_id,
          f.message_id,
          f.feedback_type,
          f.notes,
          f.original_verdict,
          f.original_score,
          f.corrected_verdict,
          f.user_email,
          f.created_at,
          t.subject,
          t.sender_email,
          t.status as threat_status
        FROM feedback f
        LEFT JOIN threats t ON f.threat_id = t.id
        WHERE f.tenant_id = ${tenantId}
        ORDER BY f.created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      const countResult = await sql`
        SELECT COUNT(*)::int as count
        FROM feedback
        WHERE tenant_id = ${tenantId}
      `;
      total = countResult[0]?.count || 0;
    }

    // Get feedback summary
    const summary = await sql`
      SELECT
        COUNT(*)::int as total,
        COUNT(*) FILTER (WHERE feedback_type = 'false_positive')::int as false_positives,
        COUNT(*) FILTER (WHERE feedback_type = 'false_negative')::int as false_negatives,
        COUNT(*) FILTER (WHERE feedback_type = 'confirmed_threat')::int as confirmed,
        COUNT(*) FILTER (WHERE feedback_type IN ('spam', 'phishing', 'malware'))::int as categorized
      FROM feedback
      WHERE tenant_id = ${tenantId}
      AND created_at >= NOW() - INTERVAL '30 days'
    `;

    return NextResponse.json({
      feedback,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
      summary: summary[0] || {
        total: 0,
        false_positives: 0,
        false_negatives: 0,
        confirmed: 0,
        categorized: 0,
      },
    });
  } catch (error) {
    console.error('Feedback list error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch feedback' },
      { status: 500 }
    );
  }
}

/**
 * POST - Submit feedback for an email by message_id
 */
export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body = await request.json();

    // Validate required fields
    if (!body.messageId) {
      return NextResponse.json(
        { error: 'messageId is required' },
        { status: 400 }
      );
    }

    const validTypes: FeedbackType[] = [
      'false_positive',
      'false_negative',
      'confirmed_threat',
      'spam',
      'phishing',
      'malware',
      'other',
    ];
    if (!validTypes.includes(body.feedbackType)) {
      return NextResponse.json(
        { error: 'Invalid feedback type' },
        { status: 400 }
      );
    }

    // Get user email
    const users = await sql`
      SELECT email FROM users WHERE clerk_user_id = ${userId} LIMIT 1
    `;
    const actorEmail = users.length > 0 ? users[0].email as string : null;

    // Find the email verdict
    const verdicts = await sql`
      SELECT message_id, verdict, score FROM email_verdicts
      WHERE message_id = ${body.messageId}
      AND tenant_id = ${tenantId}
    `;

    if (verdicts.length === 0) {
      return NextResponse.json(
        { error: 'Email not found' },
        { status: 404 }
      );
    }

    const verdict = verdicts[0];

    // Check for threat record
    const threats = await sql`
      SELECT id FROM threats
      WHERE message_id = ${body.messageId}
      AND tenant_id = ${tenantId}
      LIMIT 1
    `;
    const threatId = threats.length > 0 ? threats[0].id as string : null;

    // Insert feedback
    const feedback = await sql`
      INSERT INTO feedback (
        tenant_id,
        threat_id,
        message_id,
        user_id,
        user_email,
        feedback_type,
        notes,
        original_verdict,
        original_score,
        corrected_verdict,
        created_at
      ) VALUES (
        ${tenantId},
        ${threatId},
        ${body.messageId},
        ${userId},
        ${actorEmail},
        ${body.feedbackType},
        ${body.notes || null},
        ${verdict.verdict as string},
        ${verdict.score as number},
        ${body.correctedVerdict || null},
        NOW()
      )
      RETURNING id, created_at
    `;

    // Update threat if false positive
    if (body.feedbackType === 'false_positive' && threatId) {
      await sql`
        UPDATE threats
        SET
          status = 'dismissed',
          dismissed_at = NOW(),
          dismissed_by = ${userId},
          dismissal_reason = 'false_positive_feedback'
        WHERE id = ${threatId}
        AND tenant_id = ${tenantId}
      `;
    }

    // Update email verdict with feedback
    await sql`
      UPDATE email_verdicts
      SET
        user_feedback = ${body.feedbackType},
        updated_at = NOW()
      WHERE message_id = ${body.messageId}
      AND tenant_id = ${tenantId}
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail,
      action: 'feedback.submitted',
      resourceType: 'email',
      resourceId: body.messageId,
      beforeState: { verdict: verdict.verdict, score: verdict.score },
      afterState: {
        feedbackType: body.feedbackType,
        correctedVerdict: body.correctedVerdict,
      },
    });

    return NextResponse.json({
      success: true,
      feedbackId: feedback[0].id,
    });
  } catch (error) {
    console.error('Feedback submission error:', error);
    return NextResponse.json(
      { error: 'Failed to submit feedback' },
      { status: 500 }
    );
  }
}
