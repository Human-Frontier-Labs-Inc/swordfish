/**
 * Script to clean up cross-tenant duplicate emails
 *
 * This script addresses the security bug where the Gmail webhook fallback logic
 * incorrectly assigned emails to the wrong tenant when only one Gmail integration existed.
 *
 * The bug caused emails from cornelius@chuqlab.com to appear in thecorge@gmail.com's tenant.
 *
 * This script:
 * 1. Identifies duplicate message_ids that exist in multiple tenants
 * 2. Determines which records are incorrectly assigned (based on email address mismatch)
 * 3. Removes the incorrectly assigned records
 *
 * Run with: source .env.local && npx tsx scripts/cleanup-cross-tenant-duplicates.ts
 *
 * Add --dry-run flag to preview without deleting:
 *   npx tsx scripts/cleanup-cross-tenant-duplicates.ts --dry-run
 */

import { sql } from '@/lib/db';

interface DuplicateRecord {
  message_id: string;
  tenant_id: string;
  from_address: string;
  subject: string;
  created_at: Date;
  id: string;
}

interface ThreatDuplicateRecord {
  id: string;
  message_id: string;
  tenant_id: string;
  sender_email: string;
  subject: string;
  created_at: Date;
}

interface TenantInfo {
  tenant_id: string;
  email: string;
  count: number;
}

async function cleanupCrossTenantDuplicates() {
  const isDryRun = process.argv.includes('--dry-run');

  console.log('=== Cross-Tenant Duplicate Cleanup Script ===\n');
  console.log(`Mode: ${isDryRun ? 'DRY RUN (no changes will be made)' : 'LIVE (will delete records)'}\n`);

  // Step 1: Get tenant information
  console.log('Step 1: Identifying tenants with Gmail integrations...\n');

  const tenants = await sql`
    SELECT
      tenant_id,
      config->>'email' as email,
      COUNT(*) as count
    FROM integrations
    WHERE type = 'gmail'
    AND status = 'connected'
    GROUP BY tenant_id, config->>'email'
  ` as TenantInfo[];

  console.log('Gmail integrations by tenant:');
  for (const t of tenants) {
    console.log(`  - ${t.email}: ${t.count} integration(s) in tenant ${t.tenant_id}`);
  }
  console.log('');

  // Step 2: Find duplicate message_ids across tenants
  console.log('Step 2: Finding duplicate message_ids across tenants...\n');

  const duplicates = await sql`
    WITH duplicated_messages AS (
      SELECT message_id
      FROM email_verdicts
      GROUP BY message_id
      HAVING COUNT(DISTINCT tenant_id) > 1
    )
    SELECT
      ev.id,
      ev.message_id,
      ev.tenant_id,
      ev.from_address,
      ev.subject,
      ev.created_at
    FROM email_verdicts ev
    JOIN duplicated_messages dm ON ev.message_id = dm.message_id
    ORDER BY ev.message_id, ev.created_at
  ` as DuplicateRecord[];

  if (duplicates.length === 0) {
    console.log('No duplicate message_ids found across tenants. Database is clean!');
    return;
  }

  console.log(`Found ${duplicates.length} records with duplicate message_ids.\n`);

  // Step 3: Group by message_id and identify which to delete
  const messageGroups = new Map<string, DuplicateRecord[]>();
  for (const record of duplicates) {
    const existing = messageGroups.get(record.message_id) || [];
    existing.push(record);
    messageGroups.set(record.message_id, existing);
  }

  console.log(`These records span ${messageGroups.size} unique message_ids.\n`);

  // Step 2b: Find duplicate message_ids in threats table
  console.log('Step 2b: Finding duplicate message_ids in threats table...\n');

  const threatDuplicates = await sql`
    WITH duplicated_threats AS (
      SELECT message_id
      FROM threats
      WHERE message_id IS NOT NULL
      GROUP BY message_id
      HAVING COUNT(DISTINCT tenant_id) > 1
    )
    SELECT
      t.id,
      t.message_id,
      t.tenant_id,
      t.sender_email,
      t.subject,
      t.created_at
    FROM threats t
    JOIN duplicated_threats dt ON t.message_id = dt.message_id
    ORDER BY t.message_id, t.created_at
  ` as ThreatDuplicateRecord[];

  if (threatDuplicates.length > 0) {
    console.log(`Found ${threatDuplicates.length} threat records with duplicate message_ids.\n`);
  } else {
    console.log('No duplicate threats found across tenants.\n');
  }

  // Group threat duplicates by message_id
  const threatGroups = new Map<string, ThreatDuplicateRecord[]>();
  for (const record of threatDuplicates) {
    const existing = threatGroups.get(record.message_id) || [];
    existing.push(record);
    threatGroups.set(record.message_id, existing);
  }

  // Step 4: Determine which records to delete
  // Logic: Keep the record where from_address matches the tenant's integration email
  console.log('Step 3: Analyzing duplicates to determine correct tenant...\n');

  const toDelete: DuplicateRecord[] = [];
  const threatsToDelete: ThreatDuplicateRecord[] = [];
  const tenantEmails = new Map<string, string>();
  for (const t of tenants) {
    tenantEmails.set(t.tenant_id, t.email);
  }

  // Build domain to tenant mapping
  const domainToTenant = new Map<string, string>();
  for (const [tenantId, email] of tenantEmails) {
    const domain = email.split('@')[1]?.toLowerCase();
    if (domain) {
      domainToTenant.set(domain, tenantId);
      console.log(`Domain mapping: ${domain} => ${tenantId.substring(0, 30)}...`);
    }
  }
  console.log('');

  for (const [messageId, records] of messageGroups) {
    console.log(`Message: ${messageId.substring(0, 50)}...`);

    // Fetch to_addresses for one of the records to determine correct tenant
    const recordWithTo = await sql`
      SELECT to_addresses FROM email_verdicts WHERE id = ${records[0].id}::uuid
    ` as { to_addresses: unknown[] }[];

    const toAddresses = recordWithTo[0]?.to_addresses || [];
    let correctTenantId: string | null = null;

    // Extract recipient domain from to_addresses
    for (const addr of toAddresses) {
      let email = '';
      if (typeof addr === 'string') {
        email = addr;
      } else if (addr && typeof addr === 'object') {
        email = (addr as { address?: string; email?: string }).address ||
                (addr as { address?: string; email?: string }).email || '';
      }

      const domain = email.split('@')[1]?.toLowerCase();
      if (domain && domainToTenant.has(domain)) {
        correctTenantId = domainToTenant.get(domain)!;
        console.log(`  Recipient domain: ${domain} -> correct tenant: ${correctTenantId.substring(0, 30)}...`);
        break;
      }
    }

    for (const record of records) {
      const integrationEmail = tenantEmails.get(record.tenant_id);
      const isCorrectTenant = record.tenant_id === correctTenantId;
      console.log(`  - Tenant: ${record.tenant_id.substring(0, 30)}...`);
      console.log(`    From: ${record.from_address}`);
      console.log(`    Integration email: ${integrationEmail || 'N/A'}`);
      console.log(`    Correct owner: ${isCorrectTenant ? 'YES ✓' : 'NO ✗'}`);
      console.log(`    Created: ${record.created_at}`);
    }

    if (records.length === 2 && correctTenantId) {
      // Delete the record from the WRONG tenant
      const wrongRecord = records.find(r => r.tenant_id !== correctTenantId);
      if (wrongRecord) {
        toDelete.push(wrongRecord);
        console.log(`  → Will DELETE record from wrong tenant (${tenantEmails.get(wrongRecord.tenant_id)})`);
      }
    } else if (records.length === 2) {
      // Fall back to deleting later record if we can't determine correct tenant
      const sorted = records.sort((a, b) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
      );
      toDelete.push(sorted[1]);
      console.log(`  → Will DELETE the later record (could not determine correct tenant)`);
    } else {
      console.log(`  → Skipping: ${records.length} records found (needs manual review)`);
    }
    console.log('');
  }

  // Analyze threat duplicates
  if (threatGroups.size > 0) {
    console.log('\n--- Threat Duplicates ---\n');
    for (const [messageId, records] of threatGroups) {
      console.log(`Threat for message: ${messageId.substring(0, 50)}...`);

      for (const record of records) {
        const integrationEmail = tenantEmails.get(record.tenant_id);
        console.log(`  - Tenant: ${record.tenant_id.substring(0, 30)}...`);
        console.log(`    Sender: ${record.sender_email}`);
        console.log(`    Integration email: ${integrationEmail || 'N/A'}`);
        console.log(`    Created: ${record.created_at}`);
      }

      // Same logic: delete the later record
      if (records.length === 2) {
        const sorted = records.sort((a, b) =>
          new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
        );
        threatsToDelete.push(sorted[1]);
        console.log(`  → Will DELETE the later threat record (created ${sorted[1].created_at})`);
      } else {
        console.log(`  → Skipping: ${records.length} threat records found (needs manual review)`);
      }
      console.log('');
    }
  }

  console.log(`\n=== Summary ===`);
  console.log(`Total duplicate email_verdict message_ids: ${messageGroups.size}`);
  console.log(`Total duplicate threat message_ids: ${threatGroups.size}`);
  console.log(`Email verdicts to delete: ${toDelete.length}`);
  console.log(`Threats to delete: ${threatsToDelete.length}`);
  console.log(`Email verdicts requiring manual review: ${duplicates.length - toDelete.length * 2}`);
  console.log(`Threats requiring manual review: ${threatDuplicates.length - threatsToDelete.length * 2}`);

  if (toDelete.length === 0 && threatsToDelete.length === 0) {
    console.log('\nNo records to delete.');
    return;
  }

  // Step 5: Delete the duplicates
  if (!isDryRun) {
    console.log('\nStep 4: Deleting duplicate records...\n');

    let deletedVerdicts = 0;
    let failedVerdicts = 0;
    let deletedThreats = 0;
    let failedThreats = 0;

    // Delete email verdicts
    if (toDelete.length > 0) {
      console.log('--- Deleting Email Verdicts ---\n');
      for (const record of toDelete) {
        try {
          // First, delete any related quarantine records
          await sql`
            DELETE FROM quarantine
            WHERE verdict_id = ${record.id}::uuid
          `;

          // Then delete the email_verdict
          await sql`
            DELETE FROM email_verdicts
            WHERE id = ${record.id}::uuid
          `;

          deletedVerdicts++;
          console.log(`  ✓ Deleted verdict: ${record.subject?.substring(0, 50) || '(no subject)'}...`);
        } catch (error) {
          failedVerdicts++;
          const errorMsg = error instanceof Error ? error.message : 'Unknown error';
          console.log(`  ✗ Failed to delete verdict ${record.id}: ${errorMsg}`);
        }
      }
    }

    // Delete threats
    if (threatsToDelete.length > 0) {
      console.log('\n--- Deleting Threats ---\n');
      for (const record of threatsToDelete) {
        try {
          await sql`
            DELETE FROM threats
            WHERE id = ${record.id}::uuid
          `;

          deletedThreats++;
          console.log(`  ✓ Deleted threat: ${record.subject?.substring(0, 50) || '(no subject)'}...`);
        } catch (error) {
          failedThreats++;
          const errorMsg = error instanceof Error ? error.message : 'Unknown error';
          console.log(`  ✗ Failed to delete threat ${record.id}: ${errorMsg}`);
        }
      }
    }

    console.log(`\n=== Deletion Complete ===`);
    console.log(`Email verdicts - Successfully deleted: ${deletedVerdicts}, Failed: ${failedVerdicts}`);
    console.log(`Threats - Successfully deleted: ${deletedThreats}, Failed: ${failedThreats}`);
  } else {
    console.log('\n[DRY RUN] Would delete the following records:');

    if (toDelete.length > 0) {
      console.log('\n--- Email Verdicts ---');
      for (const record of toDelete) {
        console.log(`  - ${record.id}: "${record.subject?.substring(0, 50) || '(no subject)'}..." from ${record.from_address}`);
      }
    }

    if (threatsToDelete.length > 0) {
      console.log('\n--- Threats ---');
      for (const record of threatsToDelete) {
        console.log(`  - ${record.id}: "${record.subject?.substring(0, 50) || '(no subject)'}..." from ${record.sender_email}`);
      }
    }

    console.log('\nRun without --dry-run to actually delete these records.');
  }

  console.log('\nDone!');
}

// Run the script
cleanupCrossTenantDuplicates()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Script failed:', error);
    process.exit(1);
  });
