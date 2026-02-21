#!/usr/bin/env node

/**
 * Migration Script: Nango to Direct OAuth
 *
 * This script migrates existing Nango-managed integrations to the new
 * direct OAuth system. It:
 *
 * 1. Fetches all connections from Nango
 * 2. Retrieves tokens for each connection
 * 3. Stores tokens in the integrations table using the new columns
 * 4. Marks integrations as requiring reconnection if migration fails
 *
 * IMPORTANT: Run this script during a maintenance window as it will
 * temporarily disrupt email sync for users while their tokens are migrated.
 *
 * Usage:
 *   node scripts/migrate-nango-to-direct-oauth.mjs [--dry-run]
 *
 * Environment variables required:
 *   - DATABASE_URL
 *   - NANGO_SECRET_KEY
 *   - TOKEN_ENCRYPTION_KEY
 */

import crypto from 'crypto';

// Get environment variables
const DATABASE_URL = process.env.DATABASE_URL;
const NANGO_SECRET_KEY = process.env.NANGO_SECRET_KEY;
const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY;

const isDryRun = process.argv.includes('--dry-run');

// Simple encryption function (matching lib/security/encryption.ts)
function encrypt(text) {
  if (!TOKEN_ENCRYPTION_KEY || TOKEN_ENCRYPTION_KEY.length < 32) {
    throw new Error('TOKEN_ENCRYPTION_KEY must be at least 32 characters');
  }
  const key = Buffer.from(TOKEN_ENCRYPTION_KEY.slice(0, 32), 'utf8');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

// Database connection using pg
async function getDbClient() {
  const { default: pg } = await import('pg');
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  return client;
}

// Fetch Nango connection details
async function fetchNangoConnection(providerConfigKey, connectionId) {
  const response = await fetch(
    `https://api.nango.dev/connection/${connectionId}?provider_config_key=${providerConfigKey}`,
    {
      headers: {
        Authorization: `Bearer ${NANGO_SECRET_KEY}`,
      },
    }
  );

  if (!response.ok) {
    throw new Error(`Nango API error: ${response.status} ${response.statusText}`);
  }

  return response.json();
}

// Main migration function
async function migrate() {
  console.log('🚀 Starting Nango to Direct OAuth migration...');
  console.log(`   Mode: ${isDryRun ? 'DRY RUN (no changes will be made)' : 'LIVE'}`);
  console.log('');

  if (!DATABASE_URL) {
    console.error('❌ DATABASE_URL environment variable is required');
    process.exit(1);
  }

  if (!NANGO_SECRET_KEY) {
    console.error('❌ NANGO_SECRET_KEY environment variable is required');
    process.exit(1);
  }

  if (!TOKEN_ENCRYPTION_KEY) {
    console.error('❌ TOKEN_ENCRYPTION_KEY environment variable is required');
    process.exit(1);
  }

  const client = await getDbClient();

  try {
    // Get all integrations with Nango connections
    const result = await client.query(`
      SELECT id, tenant_id, type, nango_connection_id, config
      FROM integrations
      WHERE nango_connection_id IS NOT NULL
      AND status = 'connected'
      ORDER BY created_at
    `);

    const integrations = result.rows;
    console.log(`📊 Found ${integrations.length} integrations with Nango connections`);
    console.log('');

    let successCount = 0;
    let failCount = 0;
    let skipCount = 0;

    for (const integration of integrations) {
      const { id, tenant_id, type, nango_connection_id, config } = integration;

      // Map integration type to Nango provider key
      const providerConfigKey = type === 'gmail' ? 'google' : type === 'o365' ? 'outlook' : null;

      if (!providerConfigKey) {
        console.log(`⏭️  Skipping ${id}: Unknown integration type '${type}'`);
        skipCount++;
        continue;
      }

      console.log(`🔄 Processing ${type} integration for tenant ${tenant_id}...`);

      try {
        // Fetch connection details from Nango
        const connection = await fetchNangoConnection(providerConfigKey, nango_connection_id);

        if (!connection.credentials?.access_token || !connection.credentials?.refresh_token) {
          console.log(`   ⚠️  Missing tokens in Nango connection, marking for reconnection`);
          if (!isDryRun) {
            await client.query(`
              UPDATE integrations
              SET status = 'requires_reauth',
                  error_message = 'Migration required - please reconnect your account',
                  updated_at = NOW()
              WHERE id = $1
            `, [id]);
          }
          failCount++;
          continue;
        }

        // Get email from various possible locations
        const connectedEmail = (
          connection.connection_config?.email ||
          connection.end_user?.email ||
          config?.email ||
          ''
        ).toLowerCase();

        if (!connectedEmail) {
          console.log(`   ⚠️  No email found in Nango connection, marking for reconnection`);
          if (!isDryRun) {
            await client.query(`
              UPDATE integrations
              SET status = 'requires_reauth',
                  error_message = 'Migration required - please reconnect your account',
                  updated_at = NOW()
              WHERE id = $1
            `, [id]);
          }
          failCount++;
          continue;
        }

        // Calculate token expiry
        const expiresAt = connection.credentials.expires_at
          ? new Date(connection.credentials.expires_at)
          : new Date(Date.now() + 3600 * 1000); // Default 1 hour if not provided

        // Encrypt tokens
        const encryptedAccessToken = encrypt(connection.credentials.access_token);
        const encryptedRefreshToken = encrypt(connection.credentials.refresh_token);

        console.log(`   📧 Email: ${connectedEmail}`);
        console.log(`   🔑 Token expires: ${expiresAt.toISOString()}`);

        if (!isDryRun) {
          // Update integration with direct OAuth tokens
          await client.query(`
            UPDATE integrations
            SET oauth_access_token = $1,
                oauth_refresh_token = $2,
                oauth_token_expires_at = $3,
                oauth_scopes = $4,
                connected_email = $5,
                connected_email_verified_at = NOW(),
                updated_at = NOW()
            WHERE id = $6
          `, [
            encryptedAccessToken,
            encryptedRefreshToken,
            expiresAt,
            connection.credentials.scope || '',
            connectedEmail,
            id,
          ]);

          console.log(`   ✅ Migration successful`);
        } else {
          console.log(`   ✅ Would migrate (dry run)`);
        }

        successCount++;
      } catch (error) {
        console.log(`   ❌ Migration failed: ${error.message}`);

        if (!isDryRun) {
          // Mark for reconnection on failure
          await client.query(`
            UPDATE integrations
            SET status = 'requires_reauth',
                error_message = 'Migration failed - please reconnect your account',
                updated_at = NOW()
            WHERE id = $1
          `, [id]);
        }

        failCount++;
      }

      console.log('');
    }

    // Summary
    console.log('═══════════════════════════════════════════════════════');
    console.log('📊 MIGRATION SUMMARY');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`   Total integrations:  ${integrations.length}`);
    console.log(`   ✅ Successful:       ${successCount}`);
    console.log(`   ❌ Failed:           ${failCount}`);
    console.log(`   ⏭️  Skipped:          ${skipCount}`);
    console.log('');

    if (failCount > 0) {
      console.log('⚠️  Some integrations failed migration and have been marked');
      console.log('   as "requires_reauth". Users will need to reconnect these');
      console.log('   accounts through the dashboard.');
    }

    if (isDryRun) {
      console.log('');
      console.log('💡 This was a DRY RUN. Run without --dry-run to apply changes.');
    }

  } finally {
    await client.end();
  }
}

// Run migration
migrate().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
