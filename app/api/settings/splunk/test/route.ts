/**
 * Splunk Connection Test API
 *
 * POST /api/settings/splunk/test - Test Splunk connection
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { testSplunkConnection, SplunkConfig } from '@/lib/integrations/splunk';

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const body = await request.json();
    const { hecUrl, hecToken, index = 'main', source = 'swordfish', sourceType = 'cef' } = body;

    if (!hecUrl || !hecToken) {
      return NextResponse.json({ error: 'hecUrl and hecToken are required' }, { status: 400 });
    }

    const config: SplunkConfig = {
      id: 'test',
      tenantId,
      name: 'Test',
      hecUrl,
      hecToken,
      index,
      source,
      sourceType,
      isActive: true,
      eventTypes: ['threat'],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await testSplunkConnection(config);

    return NextResponse.json({
      success: result.success,
      error: result.error,
    });
  } catch (error) {
    console.error('Splunk test error:', error);
    return NextResponse.json(
      { error: 'Failed to test Splunk connection' },
      { status: 500 }
    );
  }
}
