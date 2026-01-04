/**
 * Settings API
 * GET - Retrieve tenant settings
 * PUT - Update tenant settings
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

export interface TenantSettings {
  // Detection thresholds
  detection: {
    suspiciousThreshold: number;
    quarantineThreshold: number;
    blockThreshold: number;
    enableLlmAnalysis: boolean;
    llmDailyLimit: number;
  };

  // Notification settings
  notifications: {
    emailEnabled: boolean;
    emailRecipients: string[];
    slackEnabled: boolean;
    slackWebhookUrl?: string;
    webhookEnabled: boolean;
    webhookUrl?: string;
    severityThreshold: 'info' | 'warning' | 'critical';
  };

  // Quarantine settings
  quarantine: {
    autoDeleteAfterDays: number;
    allowUserRelease: boolean;
    notifyOnRelease: boolean;
  };

  // Integration settings
  integrations: {
    microsoftConnected: boolean;
    googleConnected: boolean;
    webhookToken?: string;
  };

  // Display preferences
  display: {
    timezone: string;
    dateFormat: string;
    itemsPerPage: number;
  };
}

const DEFAULT_SETTINGS: TenantSettings = {
  detection: {
    suspiciousThreshold: 30,
    quarantineThreshold: 60,
    blockThreshold: 80,
    enableLlmAnalysis: true,
    llmDailyLimit: 100,
  },
  notifications: {
    emailEnabled: true,
    emailRecipients: [],
    slackEnabled: false,
    webhookEnabled: false,
    severityThreshold: 'warning',
  },
  quarantine: {
    autoDeleteAfterDays: 30,
    allowUserRelease: false,
    notifyOnRelease: true,
  },
  integrations: {
    microsoftConnected: false,
    googleConnected: false,
  },
  display: {
    timezone: 'UTC',
    dateFormat: 'YYYY-MM-DD',
    itemsPerPage: 50,
  },
};

export async function GET() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get settings from database
    const result = await sql`
      SELECT settings FROM tenant_settings
      WHERE tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (result.length === 0) {
      // Return defaults if no settings saved
      return NextResponse.json({ settings: DEFAULT_SETTINGS });
    }

    // Merge with defaults to handle new fields
    const savedSettings = result[0].settings as Partial<TenantSettings>;
    const mergedSettings: TenantSettings = {
      detection: { ...DEFAULT_SETTINGS.detection, ...savedSettings.detection },
      notifications: { ...DEFAULT_SETTINGS.notifications, ...savedSettings.notifications },
      quarantine: { ...DEFAULT_SETTINGS.quarantine, ...savedSettings.quarantine },
      integrations: { ...DEFAULT_SETTINGS.integrations, ...savedSettings.integrations },
      display: { ...DEFAULT_SETTINGS.display, ...savedSettings.display },
    };

    return NextResponse.json({ settings: mergedSettings });
  } catch (error) {
    console.error('Get settings error:', error);
    return NextResponse.json(
      { error: 'Failed to retrieve settings' },
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

    // Validate settings
    const settings = body.settings as Partial<TenantSettings>;

    // Validate thresholds
    if (settings.detection) {
      const { suspiciousThreshold, quarantineThreshold, blockThreshold } = settings.detection;

      if (suspiciousThreshold !== undefined) {
        if (suspiciousThreshold < 0 || suspiciousThreshold > 100) {
          return NextResponse.json(
            { error: 'Suspicious threshold must be between 0 and 100' },
            { status: 400 }
          );
        }
      }

      if (quarantineThreshold !== undefined) {
        if (quarantineThreshold < 0 || quarantineThreshold > 100) {
          return NextResponse.json(
            { error: 'Quarantine threshold must be between 0 and 100' },
            { status: 400 }
          );
        }
      }

      if (blockThreshold !== undefined) {
        if (blockThreshold < 0 || blockThreshold > 100) {
          return NextResponse.json(
            { error: 'Block threshold must be between 0 and 100' },
            { status: 400 }
          );
        }
      }

      // Ensure thresholds are in order
      const s = settings.detection.suspiciousThreshold ?? DEFAULT_SETTINGS.detection.suspiciousThreshold;
      const q = settings.detection.quarantineThreshold ?? DEFAULT_SETTINGS.detection.quarantineThreshold;
      const b = settings.detection.blockThreshold ?? DEFAULT_SETTINGS.detection.blockThreshold;

      if (s >= q || q >= b) {
        return NextResponse.json(
          { error: 'Thresholds must be in order: suspicious < quarantine < block' },
          { status: 400 }
        );
      }
    }

    // Validate email recipients
    if (settings.notifications?.emailRecipients) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      for (const email of settings.notifications.emailRecipients) {
        if (!emailRegex.test(email)) {
          return NextResponse.json(
            { error: `Invalid email address: ${email}` },
            { status: 400 }
          );
        }
      }
    }

    // Get current settings
    const current = await sql`
      SELECT settings FROM tenant_settings
      WHERE tenant_id = ${tenantId}
      LIMIT 1
    `;

    const currentSettings = current.length > 0
      ? current[0].settings as TenantSettings
      : DEFAULT_SETTINGS;

    // Merge settings
    const mergedSettings: TenantSettings = {
      detection: { ...currentSettings.detection, ...settings.detection },
      notifications: { ...currentSettings.notifications, ...settings.notifications },
      quarantine: { ...currentSettings.quarantine, ...settings.quarantine },
      integrations: { ...currentSettings.integrations, ...settings.integrations },
      display: { ...currentSettings.display, ...settings.display },
    };

    // Upsert settings
    await sql`
      INSERT INTO tenant_settings (tenant_id, settings, updated_at)
      VALUES (${tenantId}, ${JSON.stringify(mergedSettings)}, NOW())
      ON CONFLICT (tenant_id)
      DO UPDATE SET
        settings = ${JSON.stringify(mergedSettings)},
        updated_at = NOW()
    `;

    // Log audit event
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'settings.update',
      resourceType: 'settings',
      resourceId: tenantId,
      afterState: {
        updatedSections: Object.keys(settings),
      },
    });

    return NextResponse.json({
      success: true,
      settings: mergedSettings,
    });
  } catch (error) {
    console.error('Update settings error:', error);
    return NextResponse.json(
      { error: 'Failed to update settings' },
      { status: 500 }
    );
  }
}
