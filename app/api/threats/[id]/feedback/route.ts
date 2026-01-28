/**
 * Threat Feedback API
 * POST - Submit feedback for false positive/negative
 * GET - Get feedback history for a threat
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';
import { processFeedback } from '@/lib/feedback/feedback-learning';

interface RouteParams {
  params: Promise<{ id: string }>;
}

type FeedbackType = 'false_positive' | 'false_negative' | 'confirmed_threat' | 'spam' | 'phishing' | 'malware' | 'other';

interface FeedbackRequest {
  feedbackType: FeedbackType;
  notes?: string;
  correctedVerdict?: 'pass' | 'suspicious' | 'quarantine' | 'block';
}

/**
 * POST - Submit feedback for a threat/email
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const { id } = await params;
    const body: FeedbackRequest = await request.json();

    // Validate feedback type
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

    // Check if threat exists and belongs to tenant
    const threats = await sql`
      SELECT id, message_id, verdict, score, sender_email, subject, signals FROM threats
      WHERE id = ${id}
      AND tenant_id = ${tenantId}
    `;

    let messageId: string | null = null;
    let originalVerdict: string | null = null;
    let originalScore: number | null = null;

    if (threats.length > 0) {
      messageId = threats[0].message_id as string;
      originalVerdict = threats[0].verdict as string;
      originalScore = threats[0].score as number;
    } else {
      // Also check email_verdicts table (for emails that weren't quarantined)
      const verdicts = await sql`
        SELECT message_id, verdict, score FROM email_verdicts
        WHERE message_id = ${id}
        AND tenant_id = ${tenantId}
      `;
      if (verdicts.length > 0) {
        messageId = verdicts[0].message_id as string;
        originalVerdict = verdicts[0].verdict as string;
        originalScore = verdicts[0].score as number;
      } else {
        return NextResponse.json({ error: 'Not found' }, { status: 404 });
      }
    }

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
        ${threats.length > 0 ? id : null},
        ${messageId},
        ${userId},
        ${actorEmail},
        ${body.feedbackType},
        ${body.notes || null},
        ${originalVerdict},
        ${originalScore},
        ${body.correctedVerdict || null},
        NOW()
      )
      RETURNING id, created_at
    `;

    // Update threat status if false positive
    if (body.feedbackType === 'false_positive' && threats.length > 0) {
      await sql`
        UPDATE threats
        SET
          status = 'dismissed',
          dismissed_at = NOW(),
          dismissed_by = ${userId},
          dismissal_reason = 'false_positive_feedback'
        WHERE id = ${id}
        AND tenant_id = ${tenantId}
      `;
    }

    // Update email verdict if corrected verdict provided
    if (body.correctedVerdict && messageId) {
      await sql`
        UPDATE email_verdicts
        SET
          user_feedback = ${body.feedbackType},
          updated_at = NOW()
        WHERE message_id = ${messageId}
        AND tenant_id = ${tenantId}
      `;
    }

    // Phase 5: Process feedback for learning (async - don't block response)
    // Get sender info from threat for learning
    let senderEmail = '';
    let senderDomain = '';
    let subject = '';
    let urls: string[] = [];

    if (threats.length > 0) {
      const threat = threats[0];
      senderEmail = (threat.sender_email as string) || '';
      senderDomain = senderEmail.split('@')[1]?.toLowerCase() || '';
      subject = (threat.subject as string) || '';
      // Get URLs from threat metadata if available
      if (threat.signals && Array.isArray(threat.signals)) {
        const signals = threat.signals as Array<{ type: string; metadata?: { url?: string } }>;
        urls = signals
          .filter(s => s.type?.includes('url') && s.metadata?.url)
          .map(s => s.metadata!.url!)
          .filter(Boolean);
      }
    }

    if (senderDomain && messageId) {
      // Process in background - don't await
      processFeedback({
        feedbackId: feedback[0].id as string,
        tenantId,
        messageId,
        senderDomain,
        senderEmail,
        feedbackType: body.feedbackType,
        originalVerdict: originalVerdict || 'unknown',
        originalScore: originalScore || 0,
        subject,
        urls,
      }).catch(err => console.error('Feedback learning error:', err));
    }

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail,
      action: 'feedback.submitted',
      resourceType: 'threat',
      resourceId: id,
      beforeState: { verdict: originalVerdict, score: originalScore },
      afterState: {
        feedbackType: body.feedbackType,
        correctedVerdict: body.correctedVerdict,
      },
    });

    return NextResponse.json({
      success: true,
      feedbackId: feedback[0].id,
      message: getFeedbackMessage(body.feedbackType),
    });
  } catch (error) {
    console.error('Feedback submission error:', error);
    return NextResponse.json(
      { error: 'Failed to submit feedback' },
      { status: 500 }
    );
  }
}

/**
 * GET - Get feedback history for a threat
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const { id } = await params;

    const feedback = await sql`
      SELECT
        id,
        feedback_type,
        notes,
        original_verdict,
        original_score,
        corrected_verdict,
        user_email,
        created_at
      FROM feedback
      WHERE (threat_id = ${id} OR message_id = ${id})
      AND tenant_id = ${tenantId}
      ORDER BY created_at DESC
    `;

    return NextResponse.json({ feedback });
  } catch (error) {
    console.error('Feedback fetch error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch feedback' },
      { status: 500 }
    );
  }
}

function getFeedbackMessage(type: FeedbackType): string {
  switch (type) {
    case 'false_positive':
      return 'Thank you for reporting this as a false positive. Our system will learn from this feedback.';
    case 'false_negative':
      return 'Thank you for reporting this missed threat. We will investigate and improve detection.';
    case 'confirmed_threat':
      return 'Thank you for confirming this threat. Your feedback helps improve accuracy.';
    case 'spam':
      return 'Reported as spam. This sender will be monitored more closely.';
    case 'phishing':
      return 'Reported as phishing. We will analyze the sender and URLs.';
    case 'malware':
      return 'Reported as malware. Attachments from this sender will be scrutinized.';
    default:
      return 'Thank you for your feedback.';
  }
}
