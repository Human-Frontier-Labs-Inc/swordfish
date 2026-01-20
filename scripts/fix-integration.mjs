#!/usr/bin/env node
/**
 * Fix Gmail integration by adding email from Nango
 * Directly updates database, bypassing Vercel authentication
 */

import { neon } from '@neondatabase/serverless';
import Nango from '@nangohq/node';

const DATABASE_URL = process.env.DATABASE_URL;
const NANGO_SECRET_KEY = process.env.NANGO_SECRET_KEY;

if (!DATABASE_URL) {
  console.error('DATABASE_URL not set');
  process.exit(1);
}

if (!NANGO_SECRET_KEY) {
  console.error('NANGO_SECRET_KEY not set');
  process.exit(1);
}

const sql = neon(DATABASE_URL);
const nango = new Nango({ secretKey: NANGO_SECRET_KEY });

function getNangoIntegrationKey(integrationType) {
  const map = {
    'gmail': 'google',
    'o365': 'microsoft',
  };
  return map[integrationType] || integrationType;
}

async function fixIntegrations() {
  try {
    console.log('Finding Gmail integrations...\n');

    const integrations = await sql`
      SELECT id, tenant_id, type, config, nango_connection_id, status
      FROM integrations
      WHERE type = 'gmail' AND status = 'connected'
    `;

    if (integrations.length === 0) {
      console.log('❌ No Gmail integrations found');
      process.exit(1);
    }

    console.log(`Found ${integrations.length} Gmail integration(s)\n`);

    let updated = 0;
    let skipped = 0;
    let failed = 0;

    for (const integration of integrations) {
      console.log(`Processing integration ${integration.id}...`);

      // Check if email already exists
      const currentEmail = integration.config?.email;
      if (currentEmail) {
        console.log(`  ✓ Email already exists: ${currentEmail}`);
        skipped++;
        continue;
      }

      if (!integration.nango_connection_id) {
        console.log(`  ✗ No Nango connection ID`);
        failed++;
        continue;
      }

      try {
        // Get email from Nango
        const providerKey = getNangoIntegrationKey('gmail');
        const connection = await nango.getConnection(providerKey, integration.nango_connection_id);
        const email = connection.connection_config?.email || connection.end_user?.email;

        if (!email) {
          console.log(`  ✗ No email found in Nango connection`);
          failed++;
          continue;
        }

        console.log(`  → Found email: ${email}`);

        // Update integration
        await sql`
          UPDATE integrations
          SET config = config || ${JSON.stringify({ email })}::jsonb,
              updated_at = NOW()
          WHERE id = ${integration.id}
        `;

        console.log(`  ✓ Updated successfully`);
        updated++;
      } catch (error) {
        console.log(`  ✗ Failed: ${error.message}`);
        failed++;
      }
    }

    console.log('\n' + '='.repeat(60));
    console.log('SUMMARY:');
    console.log(`  Updated: ${updated}`);
    console.log(`  Skipped: ${skipped} (already had email)`);
    console.log(`  Failed: ${failed}`);
    console.log('='.repeat(60));

    if (updated > 0) {
      console.log('\n✅ Integrations updated! Webhooks should now work instantly.');
      console.log('   Send a test email to verify.');
    } else if (skipped > 0 && failed === 0) {
      console.log('\n✅ All integrations already have email. No fix needed.');
    }

  } catch (error) {
    console.error('Fix failed:', error);
    process.exit(1);
  }
}

fixIntegrations();
