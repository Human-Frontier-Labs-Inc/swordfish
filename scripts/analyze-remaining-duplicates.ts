/**
 * Script to analyze remaining cross-tenant duplicates
 * Determines if they are legitimate (both users received the email) or bugs
 *
 * Run with: source .env.local && npx tsx scripts/analyze-remaining-duplicates.ts
 */

import { sql } from '@/lib/db';

interface DuplicateRecord {
  id: string;
  message_id: string;
  tenant_id: string;
  from_address: string;
  to_addresses: string[];
  subject: string;
  created_at: Date;
}

interface IntegrationInfo {
  tenant_id: string;
  email: string;
}

async function analyzeDuplicates() {
  console.log('=== Analyzing Remaining Cross-Tenant Duplicates ===\n');

  // Get tenant email mappings
  const integrations = await sql`
    SELECT
      tenant_id,
      config->>'email' as email
    FROM integrations
    WHERE type = 'gmail'
    AND status = 'connected'
  ` as IntegrationInfo[];

  const tenantEmails = new Map<string, string>();
  for (const i of integrations) {
    tenantEmails.set(i.tenant_id, i.email);
  }

  console.log('Tenant Email Mappings:');
  for (const [tenantId, email] of tenantEmails) {
    console.log(`  ${tenantId.substring(0, 30)}... => ${email}`);
  }
  console.log('');

  // Find cross-tenant duplicates with full details
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
      ev.to_addresses,
      ev.subject,
      ev.created_at
    FROM email_verdicts ev
    JOIN duplicated_messages dm ON ev.message_id = dm.message_id
    ORDER BY ev.message_id, ev.created_at
  ` as DuplicateRecord[];

  if (duplicates.length === 0) {
    console.log('No cross-tenant duplicates found. Database is clean!');
    return;
  }

  // Group by message_id
  const groups = new Map<string, DuplicateRecord[]>();
  for (const record of duplicates) {
    const existing = groups.get(record.message_id) || [];
    existing.push(record);
    groups.set(record.message_id, existing);
  }

  console.log(`Found ${groups.size} message(s) with cross-tenant duplicates:\n`);

  let legitimateCount = 0;
  let bugCount = 0;

  for (const [messageId, records] of groups) {
    console.log(`\n${'='.repeat(80)}`);
    console.log(`Message ID: ${messageId.substring(0, 60)}...`);
    console.log(`Subject: ${records[0].subject?.substring(0, 60) || '(no subject)'}`);
    console.log(`From: ${records[0].from_address}`);
    console.log('');

    // Check if each tenant's integration email is in the to_addresses
    let isLegitimate = true;
    const analysis: string[] = [];

    for (const record of records) {
      const integrationEmail = tenantEmails.get(record.tenant_id);
      const toAddresses = record.to_addresses || [];

      // Check if the integration email is in the recipients
      // to_addresses might be objects with email/name, plain strings, or other formats
      const emailInToList = toAddresses.some(addr => {
        if (!addr) return false;
        let addrStr: string;
        if (typeof addr === 'string') {
          addrStr = addr;
        } else if (typeof addr === 'object' && addr !== null) {
          addrStr = (addr as { email?: string }).email || JSON.stringify(addr);
        } else {
          addrStr = String(addr);
        }
        return addrStr.toLowerCase().includes(integrationEmail?.toLowerCase() || '');
      });

      console.log(`  Tenant: ${record.tenant_id.substring(0, 35)}...`);
      console.log(`    Integration Email: ${integrationEmail || 'N/A'}`);
      console.log(`    To Addresses: ${JSON.stringify(toAddresses)}`);
      console.log(`    Email in To List: ${emailInToList ? 'YES ✓' : 'NO ✗'}`);
      console.log(`    Created: ${record.created_at}`);
      console.log('');

      if (!emailInToList) {
        isLegitimate = false;
        analysis.push(`${integrationEmail} NOT in to_addresses`);
      } else {
        analysis.push(`${integrationEmail} found in to_addresses`);
      }
    }

    if (isLegitimate) {
      console.log('  >>> VERDICT: LEGITIMATE - Both users received this email');
      console.log('      Both integration emails appear in their respective to_addresses');
      legitimateCount++;
    } else {
      console.log('  >>> VERDICT: POTENTIAL BUG - Email may have been incorrectly assigned');
      console.log(`      Analysis: ${analysis.join(' | ')}`);
      bugCount++;
    }
  }

  console.log(`\n${'='.repeat(80)}`);
  console.log('\n=== SUMMARY ===');
  console.log(`Total cross-tenant duplicates: ${groups.size}`);
  console.log(`Legitimate shared emails: ${legitimateCount}`);
  console.log(`Potential bugs: ${bugCount}`);

  if (legitimateCount > 0 && bugCount === 0) {
    console.log('\nAll duplicates appear to be legitimate shared emails where both users');
    console.log('are valid recipients. No cleanup needed for these records.');
  } else if (bugCount > 0) {
    console.log('\nSome duplicates may be bugs that need investigation or cleanup.');
  }
}

analyzeDuplicates()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Script failed:', error);
    process.exit(1);
  });
