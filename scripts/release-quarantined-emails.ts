/**
 * Script to release all quarantined emails from the last 48 hours
 *
 * This script:
 * 1. Finds all threats with status 'quarantined' or 'deleted' from last 48 hours
 * 2. Releases them back to the user's inbox
 * 3. Updates their status to 'released'
 *
 * Run with: npx tsx scripts/release-quarantined-emails.ts
 */

import { sql } from '@/lib/db';
import { releaseEmail } from '@/lib/workers/remediation';

interface ThreatRecord {
  id: string;
  tenant_id: string;
  message_id: string;
  subject: string | null;
  sender_email: string | null;
  status: string;
  integration_type: string | null;
  created_at: Date;
}

async function releaseQuarantinedEmails() {
  console.log('=== Release Quarantined Emails Script ===\n');
  console.log('Finding quarantined/deleted emails from last 48 hours...\n');

  // Find all quarantined or deleted threats from last 48 hours
  const threats = await sql`
    SELECT id, tenant_id, message_id, subject, sender_email, status, integration_type, created_at
    FROM threats
    WHERE status IN ('quarantined', 'deleted')
    AND created_at >= NOW() - INTERVAL '48 hours'
    ORDER BY created_at DESC
  ` as ThreatRecord[];

  console.log(`Found ${threats.length} emails to release:\n`);

  if (threats.length === 0) {
    console.log('No quarantined emails found in the last 48 hours.');
    return;
  }

  // Display the emails
  for (const threat of threats) {
    console.log(`- [${threat.status}] "${threat.subject || '(no subject)'}" from ${threat.sender_email || 'unknown'}`);
    console.log(`  Created: ${threat.created_at}`);
  }

  console.log('\n--- Starting Release Process ---\n');

  let released = 0;
  let failed = 0;
  const errors: Array<{ id: string; subject: string | null; error: string }> = [];

  for (const threat of threats) {
    try {
      console.log(`Releasing: "${threat.subject || '(no subject)'}"...`);

      const result = await releaseEmail({
        tenantId: threat.tenant_id,
        threatId: threat.id,
        actorId: 'system-recalibration',
        actorEmail: null,
      });

      if (result.success) {
        released++;
        console.log(`  ✓ Released successfully`);
      } else {
        failed++;
        errors.push({ id: threat.id, subject: threat.subject, error: result.error || 'Unknown error' });
        console.log(`  ✗ Failed: ${result.error}`);
      }
    } catch (error) {
      failed++;
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push({ id: threat.id, subject: threat.subject, error: errorMsg });
      console.log(`  ✗ Error: ${errorMsg}`);
    }
  }

  console.log('\n=== Summary ===');
  console.log(`Total emails: ${threats.length}`);
  console.log(`Released: ${released}`);
  console.log(`Failed: ${failed}`);

  if (errors.length > 0) {
    console.log('\nFailed releases:');
    for (const err of errors) {
      console.log(`- "${err.subject}": ${err.error}`);
    }
  }

  console.log('\nDone!');
}

// Run the script
releaseQuarantinedEmails()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Script failed:', error);
    process.exit(1);
  });
