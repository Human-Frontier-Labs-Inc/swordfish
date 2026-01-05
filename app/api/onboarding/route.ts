/**
 * Onboarding API
 * Track and manage user onboarding progress
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

export async function GET() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    const result = await sql`
      SELECT
        current_step,
        completed_steps,
        skipped_steps,
        completed_at,
        metadata
      FROM onboarding_progress
      WHERE tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (result.length === 0) {
      return NextResponse.json({
        currentStep: 1,
        completedSteps: [],
        skippedSteps: [],
        completed: false,
      });
    }

    const row = result[0];
    const metadata = row.metadata || {};
    return NextResponse.json({
      currentStep: row.current_step,
      completedSteps: row.completed_steps || [],
      skippedSteps: row.skipped_steps || [],
      completed: row.completed_at !== null,
      metadata: metadata,
      accountType: metadata.accountType || null,
      isMsp: metadata.accountType === 'msp',
    });
  } catch (error) {
    console.error('Get onboarding error:', error);
    return NextResponse.json(
      { error: 'Failed to get onboarding status' },
      { status: 500 }
    );
  }
}

export async function PUT(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body = await request.json();
    const { currentStep, completedStep, skippedStep, completed, metadata, accountType } = body;

    // Get current progress
    const current = await sql`
      SELECT
        id,
        completed_steps,
        skipped_steps,
        metadata
      FROM onboarding_progress
      WHERE tenant_id = ${tenantId}
      LIMIT 1
    `;

    const existingData = current.length > 0 ? current[0] : null;
    const completedSteps = existingData?.completed_steps || [];
    const skippedSteps = existingData?.skipped_steps || [];
    const existingMetadata = existingData?.metadata || {};

    // Add completed step if provided
    if (completedStep && !completedSteps.includes(completedStep)) {
      completedSteps.push(completedStep);
    }

    // Add skipped step if provided
    if (skippedStep && !skippedSteps.includes(skippedStep)) {
      skippedSteps.push(skippedStep);
    }

    // Merge metadata with accountType
    const mergedMetadata = {
      ...existingMetadata,
      ...metadata,
      ...(accountType && { accountType, isMsp: accountType === 'msp' }),
    };

    if (existingData) {
      // Update existing record
      await sql`
        UPDATE onboarding_progress
        SET
          current_step = ${currentStep || existingData.current_step},
          completed_steps = ${completedSteps},
          skipped_steps = ${skippedSteps},
          completed_at = ${completed ? new Date().toISOString() : null},
          metadata = ${JSON.stringify(mergedMetadata)},
          updated_at = NOW()
        WHERE tenant_id = ${tenantId}
      `;
    } else {
      // Create new record
      await sql`
        INSERT INTO onboarding_progress (
          tenant_id,
          user_id,
          current_step,
          completed_steps,
          skipped_steps,
          completed_at,
          metadata
        ) VALUES (
          ${tenantId},
          ${userId},
          ${currentStep || 1},
          ${completedSteps},
          ${skippedSteps},
          ${completed ? new Date().toISOString() : null},
          ${JSON.stringify(mergedMetadata)}
        )
      `;
    }

    // Log completion
    if (completed) {
      await logAuditEvent({
        tenantId,
        actorId: userId,
        actorEmail: null,
        action: 'onboarding.completed',
        resourceType: 'onboarding',
        resourceId: tenantId,
        afterState: {
          completedSteps,
          skippedSteps,
        },
      });
    }

    return NextResponse.json({
      success: true,
      currentStep,
      completedSteps,
      skippedSteps,
      completed: !!completed,
    });
  } catch (error) {
    console.error('Update onboarding error:', error);
    return NextResponse.json(
      { error: 'Failed to update onboarding' },
      { status: 500 }
    );
  }
}
