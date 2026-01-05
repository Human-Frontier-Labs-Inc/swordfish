/**
 * VIP Bulk Import API
 * Import VIPs from directory sync or CSV
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { bulkImportVIPs, detectPotentialVIP } from '@/lib/detection/bec/vip-list';

interface ImportEntry {
  email: string;
  displayName: string;
  title?: string;
  department?: string;
}

/**
 * POST /api/settings/vip/import
 * Bulk import VIPs from directory or CSV data
 */
export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;
    const body = await request.json();

    if (!body.entries || !Array.isArray(body.entries)) {
      return NextResponse.json(
        { error: 'Missing required field: entries (array)' },
        { status: 400 }
      );
    }

    // Validate entries
    const validEntries: ImportEntry[] = [];
    const invalidEntries: Array<{ entry: unknown; reason: string }> = [];

    for (const entry of body.entries) {
      if (!entry.email || !entry.displayName) {
        invalidEntries.push({
          entry,
          reason: 'Missing email or displayName',
        });
        continue;
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(entry.email)) {
        invalidEntries.push({
          entry,
          reason: 'Invalid email format',
        });
        continue;
      }

      validEntries.push({
        email: entry.email,
        displayName: entry.displayName,
        title: entry.title,
        department: entry.department,
      });
    }

    // If autoDetect is enabled, only import entries that look like VIPs
    const entriesToImport = body.autoDetect
      ? validEntries.filter(e => detectPotentialVIP(e.displayName, e.title).isPotentialVIP)
      : validEntries;

    const result = await bulkImportVIPs(tenantId, entriesToImport);

    return NextResponse.json({
      imported: result.imported,
      skipped: result.skipped,
      invalidEntries: invalidEntries.length,
      totalProcessed: body.entries.length,
      autoDetect: body.autoDetect || false,
    });
  } catch (error) {
    console.error('Failed to import VIPs:', error);
    return NextResponse.json(
      { error: 'Failed to import VIPs' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/settings/vip/import/preview
 * Preview which entries would be imported as VIPs
 */
export async function PUT(request: NextRequest) {
  try {
    const { userId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();

    if (!body.entries || !Array.isArray(body.entries)) {
      return NextResponse.json(
        { error: 'Missing required field: entries (array)' },
        { status: 400 }
      );
    }

    const preview = body.entries.map((entry: ImportEntry) => {
      const detection = detectPotentialVIP(entry.displayName, entry.title);
      return {
        email: entry.email,
        displayName: entry.displayName,
        title: entry.title,
        department: entry.department,
        isPotentialVIP: detection.isPotentialVIP,
        suggestedRole: detection.suggestedRole,
        matchedTitle: detection.matchedTitle,
      };
    });

    const potentialVIPs = preview.filter((p: { isPotentialVIP: boolean }) => p.isPotentialVIP);

    return NextResponse.json({
      total: preview.length,
      potentialVIPs: potentialVIPs.length,
      preview,
    });
  } catch (error) {
    console.error('Failed to preview VIP import:', error);
    return NextResponse.json(
      { error: 'Failed to preview VIP import' },
      { status: 500 }
    );
  }
}
