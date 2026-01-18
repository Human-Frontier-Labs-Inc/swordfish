/**
 * REST API v1 - Phish Report Add-in Manifests Endpoint
 *
 * GET /api/v1/report-phish/manifests?type=outlook - Get Outlook Add-in manifest XML
 * GET /api/v1/report-phish/manifests?type=gmail - Get Gmail Add-on manifest JSON
 * GET /api/v1/report-phish/manifests?type=gmail&include=script - Include Apps Script code
 */

import { NextRequest, NextResponse } from 'next/server';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders } from '@/lib/api/rate-limit';
import { apiSuccess, errors, withErrorHandling } from '@/lib/api/response';
import {
  generateOutlookManifest,
  generateGmailManifest,
  generateGmailAppsScript,
} from '@/lib/reporting/phish-button';

// Additional scopes for phish reports
const PHISH_REPORTS_READ = 'phish_reports:read';

/**
 * GET /api/v1/report-phish/manifests
 * Generate and return add-in manifests for Outlook or Gmail
 */
export async function GET(request: NextRequest) {
  return withErrorHandling(async () => {
    // Validate API key
    const auth = await validateApiKey(request);
    if (!auth.valid) {
      return errors.unauthorized(auth.error);
    }

    // Check scope - allow threats:read or phish_reports:read (manifests are read-only)
    if (!hasScope(auth.scopes!, API_SCOPES.THREATS_READ) && !hasScope(auth.scopes!, PHISH_REPORTS_READ)) {
      return errors.invalidScope(`${API_SCOPES.THREATS_READ} or ${PHISH_REPORTS_READ}`);
    }

    // Check rate limit
    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    // Parse query parameters
    const searchParams = request.nextUrl.searchParams;
    const manifestType = searchParams.get('type');
    const includeScript = searchParams.get('include') === 'script';
    const format = searchParams.get('format') || 'json'; // 'json' or 'raw'

    if (!manifestType || !['outlook', 'gmail'].includes(manifestType)) {
      return errors.badRequest('Invalid or missing type parameter. Must be: outlook or gmail');
    }

    // Determine base URL from request or environment
    const baseUrl = process.env.NEXT_PUBLIC_APP_URL ||
      `${request.nextUrl.protocol}//${request.nextUrl.host}`;

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');

    if (manifestType === 'outlook') {
      const manifest = generateOutlookManifest(auth.tenantId!, baseUrl);

      // Return raw XML if requested
      if (format === 'raw') {
        return new NextResponse(manifest.xml, {
          status: 200,
          headers: {
            'Content-Type': 'application/xml',
            'Content-Disposition': `attachment; filename="swordfish-phish-report-${auth.tenantId}.xml"`,
            ...headers,
          },
        });
      }

      return apiSuccess({
        manifest: {
          type: manifest.type,
          version: manifest.version,
          tenantId: manifest.tenantId,
          content: manifest.xml,
          contentType: 'application/xml',
          instructions: {
            deployment: [
              '1. Download this manifest file',
              '2. Go to Microsoft 365 Admin Center > Settings > Integrated apps',
              '3. Click "Upload custom apps" and select the manifest file',
              '4. Follow the deployment wizard to assign to users/groups',
              '5. Users will see "Report Phish" button in Outlook ribbon',
            ],
            testingUrl: `${baseUrl}/addins/outlook/taskpane?tenantId=${auth.tenantId}`,
          },
        },
      }, undefined, headers);
    }

    if (manifestType === 'gmail') {
      const manifest = generateGmailManifest(auth.tenantId!, baseUrl);

      const response: {
        manifest: {
          type: string;
          version: string;
          tenantId: string;
          content: unknown;
          contentType: string;
          instructions: {
            deployment: string[];
            requirements: string[];
          };
        };
        appsScript?: {
          code: string;
          filename: string;
        };
      } = {
        manifest: {
          type: manifest.type,
          version: manifest.version,
          tenantId: manifest.tenantId,
          content: manifest.json,
          contentType: 'application/json',
          instructions: {
            deployment: [
              '1. Go to Google Apps Script (script.google.com)',
              '2. Create a new project',
              '3. Replace the Code.gs content with the provided Apps Script code',
              '4. Add appsscript.json manifest to the project',
              '5. Deploy as a Gmail Add-on (Publish > Deploy as add-on)',
              '6. Configure OAuth consent screen if needed',
              '7. Users can install from G Suite Marketplace or direct link',
            ],
            requirements: [
              'Google Workspace account with Gmail',
              'Admin approval may be required for organization-wide deployment',
              'OAuth consent must be configured for your domain',
            ],
          },
        },
      };

      // Include Apps Script code if requested
      if (includeScript) {
        // Note: In production, you'd want to generate a specific API key for this add-on
        // For now, we include a placeholder that admins should replace
        const appsScript = generateGmailAppsScript(
          auth.tenantId!,
          baseUrl,
          'YOUR_API_KEY_HERE' // Placeholder - admin must configure
        );

        response.appsScript = {
          code: appsScript,
          filename: 'Code.gs',
        };
      }

      // Return raw JSON if requested
      if (format === 'raw') {
        return new NextResponse(JSON.stringify(manifest.json, null, 2), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Content-Disposition': `attachment; filename="appsscript-${auth.tenantId}.json"`,
            ...headers,
          },
        });
      }

      return apiSuccess(response, undefined, headers);
    }

    // Should not reach here due to earlier validation
    return errors.badRequest('Invalid manifest type');
  });
}
