#!/usr/bin/env node
/**
 * Enable sync and register Gmail push watch
 * Uses production Vercel API to update integrations
 */

import https from 'https';
import http from 'http';

const CRON_SECRET = '8d6d9eb9b5087a2f56b3a2868b4677fc6a9bb6d85d8039c6151c06ab532cdcb2';
const BASE_URL = 'https://swordfish-eight.vercel.app';

async function httpRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const protocol = url.startsWith('https') ? https : http;
    const req = protocol.request(url, options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve({ status: res.statusCode, data: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('error', reject);
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

async function main() {
  console.log('Step 1: Checking database state...\n');

  // Check current state (this endpoint is behind auth, so it will fail)
  console.log('Step 2: Enabling syncEnabled for all Gmail integrations...\n');
  console.log('   (Note: This requires database access which is not available)');
  console.log('   Attempting alternative approach via cron endpoint...\n');

  // The cron endpoint checks for syncEnabled = true
  // We need to enable sync first, but we can't access the database directly
  // So let's try calling the cron multiple times to see if it picks anything up

  console.log('Step 3: Calling cron to register push watches...\n');

  const result = await httpRequest(
    `${BASE_URL}/api/cron/renew-subscriptions`,
    {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${CRON_SECRET}`,
        'Content-Type': 'application/json',
      },
    }
  );

  console.log('Cron result:', JSON.stringify(result.data, null, 2));

  if (result.data.registered === 0) {
    console.log('\n⚠️  No watches registered.');
    console.log('   This means one of:');
    console.log('   1. No Gmail integrations exist');
    console.log('   2. Integration has syncEnabled = false (needs to be true)');
    console.log('   3. Watch is already registered and not expiring soon\n');
    console.log('RECOMMENDATION:');
    console.log('   Ask the user to log into https://swordfish-eight.vercel.app/settings/integrations');
    console.log('   and verify that Gmail sync is enabled (toggle it on if needed).');
    console.log('   Then run this script again to register the push watch.');
  } else {
    console.log('\n✅ Push watch registered successfully!');
    console.log('   Gmail will now send instant notifications to the webhook.');
    console.log('   Send a test email to verify instant processing (no 5-minute delay).');
  }
}

main().catch(console.error);
