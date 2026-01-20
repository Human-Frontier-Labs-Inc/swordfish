#!/usr/bin/env node
/**
 * Direct database query to check Gmail integration state
 * Bypasses Vercel authentication
 */

import { neon } from '@neondatabase/serverless';

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('DATABASE_URL not set');
  process.exit(1);
}

const sql = neon(DATABASE_URL);

async function checkIntegrations() {
  try {
    console.log('Querying Gmail integrations...\n');

    const integrations = await sql`
      SELECT
        id,
        tenant_id,
        type,
        status,
        config,
        nango_connection_id,
        created_at,
        last_sync_at,
        updated_at
      FROM integrations
      WHERE type = 'gmail'
      ORDER BY created_at DESC
    `;

    console.log(`Found ${integrations.length} Gmail integration(s)\n`);

    for (const integration of integrations) {
      console.log('='.repeat(60));
      console.log(`Integration ID: ${integration.id}`);
      console.log(`Tenant ID: ${integration.tenant_id}`);
      console.log(`Status: ${integration.status}`);
      console.log(`Nango Connection ID: ${integration.nango_connection_id || 'MISSING'}`);
      console.log(`Email in config: ${integration.config?.email || 'MISSING'}`);
      console.log(`Full config: ${JSON.stringify(integration.config, null, 2)}`);
      console.log(`Last sync: ${integration.last_sync_at || 'Never'}`);
      console.log(`Created: ${integration.created_at}`);
      console.log(`Updated: ${integration.updated_at}`);

      // Check for problems
      const problems = [];
      if (!integration.nango_connection_id) {
        problems.push('❌ No Nango connection ID');
      }
      if (!integration.config?.email) {
        problems.push('❌ No email in config (webhook will fail to match)');
      }
      if (integration.status !== 'connected') {
        problems.push(`❌ Status is '${integration.status}' (should be 'connected')`);
      }

      if (problems.length > 0) {
        console.log('\n⚠️  PROBLEMS FOUND:');
        problems.forEach(p => console.log(`   ${p}`));
      } else {
        console.log('\n✅ Integration looks healthy');
      }
      console.log('='.repeat(60));
      console.log();
    }

    if (integrations.length === 0) {
      console.log('❌ No Gmail integrations found in database');
      return;
    }

    // Provide recommendation
    const needsFix = integrations.some(i => !i.config?.email);
    if (needsFix) {
      console.log('\n🔧 RECOMMENDATION:');
      console.log('   The integration is missing email in config.');
      console.log('   This causes webhooks to fail with "No active integration found".');
      console.log('   Run: npm run fix-integration');
    } else {
      console.log('\n✅ All integrations have email in config.');
      console.log('   If webhooks still not working, check:');
      console.log('   1. Google Pub/Sub subscription is active');
      console.log('   2. Webhook endpoint is receiving notifications');
      console.log('   3. Vercel function logs for errors');
    }

  } catch (error) {
    console.error('Database query failed:', error);
    process.exit(1);
  }
}

checkIntegrations();
