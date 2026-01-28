/**
 * Feedback Analytics API
 * GET - Get comprehensive feedback analytics and learning insights
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getFeedbackAnalytics } from '@/lib/feedback/feedback-learning';

/**
 * GET - Get feedback analytics for the tenant
 */
export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get comprehensive analytics
    const analytics = await getFeedbackAnalytics(tenantId);

    return NextResponse.json({
      success: true,
      analytics,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Feedback analytics error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch feedback analytics' },
      { status: 500 }
    );
  }
}
