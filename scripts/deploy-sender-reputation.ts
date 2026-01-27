#!/usr/bin/env tsx
/**
 * Deploy Sender Reputation System (Phase 1)
 * Runs migration 015 and seeds trusted sender database
 */
import { neon } from '@neondatabase/serverless';
import * as fs from 'fs';
import * as path from 'path';
import { TRUSTED_SENDERS } from '../lib/reputation/seed-data';

async function deploySenderReputation() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    console.error('❌ DATABASE_URL environment variable is required');
    console.error('Usage: DATABASE_URL="postgresql://..." npx tsx scripts/deploy-sender-reputation.ts');
    process.exit(1);
  }

  console.log('🚀 Deploying Sender Reputation System (Phase 1: False Positive Reduction)');
  console.log('📊 Database:', databaseUrl.split('@')[1]?.split('/')[0] || 'unknown');
  console.log();

  const sql = neon(databaseUrl);

  try {
    // Step 1: Run Migration 015
    console.log('📝 Step 1/2: Running migration 015...');
    const migrationPath = path.join(process.cwd(), 'lib/db/migrations/015_sender_reputation.sql');
    const migrationSQL = fs.readFileSync(migrationPath, 'utf-8');

    const statements = migrationSQL
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));

    let executedCount = 0;
    for (const statement of statements) {
      await sql.query(statement + ';');
      executedCount++;
      if (executedCount % 5 === 0) {
        console.log(`  ✓ Executed ${executedCount}/${statements.length} statements...`);
      }
    }

    console.log(`✅ Migration complete (${executedCount} statements executed)`);
    console.log();

    // Verify tables created
    const tables = await sql`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name IN ('sender_reputation', 'email_feedback')
      ORDER BY table_name
    `;

    console.log('📋 Tables verified:');
    tables.forEach((row: any) => {
      console.log(`  ✓ ${row.table_name}`);
    });
    console.log();

    // Step 2: Seed Trusted Senders
    console.log('🌱 Step 2/2: Seeding trusted sender database...');
    console.log(`📝 Inserting ${TRUSTED_SENDERS.length} trusted senders...`);

    let insertedCount = 0;
    let updatedCount = 0;

    for (const sender of TRUSTED_SENDERS) {
      const result = await sql`
        INSERT INTO sender_reputation (
          domain,
          display_name,
          category,
          trust_score,
          known_tracking_domains,
          email_types
        ) VALUES (
          ${sender.domain},
          ${sender.display_name},
          ${sender.category},
          ${sender.trust_score},
          ${JSON.stringify(sender.known_tracking_domains)},
          ${JSON.stringify(sender.email_types)}
        )
        ON CONFLICT (domain)
        DO UPDATE SET
          display_name = EXCLUDED.display_name,
          category = EXCLUDED.category,
          trust_score = EXCLUDED.trust_score,
          known_tracking_domains = EXCLUDED.known_tracking_domains,
          email_types = EXCLUDED.email_types,
          updated_at = NOW()
        RETURNING (xmax = 0) AS inserted
      `;

      if (result[0]?.inserted) {
        insertedCount++;
      } else {
        updatedCount++;
      }

      if ((insertedCount + updatedCount) % 25 === 0) {
        console.log(`  ✓ Processed ${insertedCount + updatedCount}/${TRUSTED_SENDERS.length}...`);
      }
    }

    console.log(`✅ Seeding complete!`);
    console.log(`  📥 Inserted: ${insertedCount} new senders`);
    console.log(`  🔄 Updated: ${updatedCount} existing senders`);
    console.log();

    // Show statistics
    const categoryStats = await sql`
      SELECT
        category,
        COUNT(*) as count,
        ROUND(AVG(trust_score)::numeric, 1) as avg_trust_score,
        MIN(trust_score) as min_trust,
        MAX(trust_score) as max_trust
      FROM sender_reputation
      GROUP BY category
      ORDER BY avg_trust_score DESC
    `;

    console.log('📊 Sender Reputation Statistics:');
    console.log('Category          | Count | Avg Trust | Range');
    console.log('------------------|-------|-----------|----------');
    categoryStats.forEach((row: any) => {
      const range = `${row.min_trust}-${row.max_trust}`;
      console.log(
        `${row.category.padEnd(17)} | ${String(row.count).padStart(5)} | ${String(row.avg_trust_score).padStart(9)} | ${range.padStart(8)}`
      );
    });
    console.log();

    // Show total
    const [totalResult] = await sql`SELECT COUNT(*) as total FROM sender_reputation`;
    console.log(`📈 Total trusted senders: ${totalResult.total}`);
    console.log();

    // Show critical senders for Quora false positive fix
    const criticalSenders = await sql`
      SELECT domain, display_name, category, trust_score
      FROM sender_reputation
      WHERE domain IN ('quora.com', 'google.com', 'github.com', 'stripe.com', 'linkedin.com')
      ORDER BY trust_score DESC
    `;

    console.log('🎯 Critical senders for FP reduction:');
    criticalSenders.forEach((row: any) => {
      console.log(`  ✓ ${row.display_name.padEnd(15)} (${row.domain.padEnd(20)}) - Trust: ${row.trust_score} [${row.category}]`);
    });
    console.log();

    console.log('✨ Deployment complete!');
    console.log();
    console.log('📋 Next steps:');
    console.log('  1. Test with Quora email sample to verify FP reduction');
    console.log('  2. Monitor production for false positive rate changes');
    console.log('  3. Track false negative rate (should remain <1%)');
    console.log('  4. Deploy to production when testing confirms expected behavior');
    console.log();
    console.log('🎯 Expected Impact:');
    console.log('  - Quora emails: Score 51 → ~25 (PASS instead of SUSPICIOUS)');
    console.log('  - Marketing FP reduction: ~60%');
    console.log('  - False negative rate: <1% (maintained)');

  } catch (error) {
    console.error('\n❌ Deployment failed:', error);
    throw error;
  }
}

deploySenderReputation().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
