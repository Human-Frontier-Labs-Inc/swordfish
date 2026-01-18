/**
 * Domain-Wide Monitoring API
 * GET - Get domain-wide config status
 * POST - Setup domain-wide monitoring
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  getDomainConfigByTenant,
  getMonitoredDomainUsers,
} from '@/lib/integrations/domain-wide/storage';
import { setupGoogleWorkspace, syncGoogleWorkspaceUsers } from '@/lib/integrations/domain-wide/google-workspace';
import { setupMicrosoft365, syncMicrosoft365Users } from '@/lib/integrations/domain-wide/microsoft-365';
import type { DomainProvider } from '@/lib/integrations/domain-wide/types';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const provider = request.nextUrl.searchParams.get('provider') as DomainProvider | null;

    if (!provider) {
      // Return both configs
      const [google, microsoft] = await Promise.all([
        getDomainConfigByTenant(tenantId, 'google_workspace'),
        getDomainConfigByTenant(tenantId, 'microsoft_365'),
      ]);

      return NextResponse.json({
        google_workspace: google ? {
          id: google.id,
          status: google.status,
          errorMessage: google.errorMessage,
          totalUsers: google.totalUsersDiscovered,
          activeUsers: google.totalUsersActive,
          lastUserSync: google.lastUserSyncAt,
          lastEmailSync: google.lastEmailSyncAt,
          serviceAccountEmail: google.googleServiceAccountEmail,
          adminEmail: google.googleAdminEmail,
        } : null,
        microsoft_365: microsoft ? {
          id: microsoft.id,
          status: microsoft.status,
          errorMessage: microsoft.errorMessage,
          totalUsers: microsoft.totalUsersDiscovered,
          activeUsers: microsoft.totalUsersActive,
          lastUserSync: microsoft.lastUserSyncAt,
          lastEmailSync: microsoft.lastEmailSyncAt,
          azureTenantId: microsoft.azureTenantId,
          clientId: microsoft.azureClientId,
        } : null,
      });
    }

    const config = await getDomainConfigByTenant(tenantId, provider);

    if (!config) {
      return NextResponse.json({ configured: false });
    }

    const users = await getMonitoredDomainUsers(config.id);

    return NextResponse.json({
      configured: true,
      id: config.id,
      status: config.status,
      errorMessage: config.errorMessage,
      totalUsers: config.totalUsersDiscovered,
      activeUsers: config.totalUsersActive,
      monitoredUsers: users.length,
      lastUserSync: config.lastUserSyncAt,
      lastEmailSync: config.lastEmailSyncAt,
      settings: {
        syncEnabled: config.syncEnabled,
        syncAllUsers: config.syncAllUsers,
        monitorIncoming: config.monitorIncoming,
        monitorOutgoing: config.monitorOutgoing,
        monitorInternal: config.monitorInternal,
      },
    });
  } catch (error) {
    console.error('Domain-wide config GET error:', error);
    return NextResponse.json(
      { error: 'Failed to get domain config' },
      { status: 500 }
    );
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
    const { provider, ...params } = body;

    if (!provider || !['google_workspace', 'microsoft_365'].includes(provider)) {
      return NextResponse.json(
        { error: 'Invalid provider. Must be "google_workspace" or "microsoft_365"' },
        { status: 400 }
      );
    }

    let result;

    if (provider === 'google_workspace') {
      const { serviceAccountKey, adminEmail } = params;

      if (!serviceAccountKey || !adminEmail) {
        return NextResponse.json(
          { error: 'Missing required fields: serviceAccountKey, adminEmail' },
          { status: 400 }
        );
      }

      result = await setupGoogleWorkspace({
        tenantId,
        serviceAccountKey,
        adminEmail,
        createdBy: userId,
      });
    } else {
      const { azureTenantId, clientId, clientSecret } = params;

      if (!azureTenantId || !clientId || !clientSecret) {
        return NextResponse.json(
          { error: 'Missing required fields: azureTenantId, clientId, clientSecret' },
          { status: 400 }
        );
      }

      result = await setupMicrosoft365({
        tenantId,
        azureTenantId,
        clientId,
        clientSecret,
        createdBy: userId,
      });
    }

    if (!result.success) {
      return NextResponse.json(
        { error: result.error, configId: result.configId },
        { status: 400 }
      );
    }

    // Trigger initial user sync
    if (provider === 'google_workspace') {
      await syncGoogleWorkspaceUsers(result.configId);
    } else {
      await syncMicrosoft365Users(result.configId);
    }

    return NextResponse.json({
      success: true,
      configId: result.configId,
      message: `${provider === 'google_workspace' ? 'Google Workspace' : 'Microsoft 365'} domain-wide monitoring configured successfully`,
    });
  } catch (error) {
    console.error('Domain-wide setup error:', error);
    return NextResponse.json(
      { error: 'Failed to setup domain-wide monitoring' },
      { status: 500 }
    );
  }
}
