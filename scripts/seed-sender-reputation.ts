import { neon } from '@neondatabase/serverless';
import { TRUSTED_SENDERS } from '../lib/reputation/seed-data';

async function seedSenderReputation() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    console.error('❌ DATABASE_URL environment variable is required');
    console.error('Usage: DATABASE_URL="postgresql://..." npx tsx scripts/seed-sender-reputation.ts');
    process.exit(1);
  }

  console.log('🌱 Seeding sender_reputation table');
  console.log(`📊 Database: ${databaseUrl.split('@')[1]?.split('/')[0] || 'unknown'}`);
  console.log(`📝 Senders to insert: ${TRUSTED_SENDERS.length}`);

  const sql = neon(databaseUrl);

  try {
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

      if ((insertedCount + updatedCount) % 20 === 0) {
        console.log(`  ✓ Processed ${insertedCount + updatedCount}/${TRUSTED_SENDERS.length} senders...`);
      }
    }

    console.log(`\n✅ Seeding complete!`);
    console.log(`  📥 Inserted: ${insertedCount} new senders`);
    console.log(`  🔄 Updated: ${updatedCount} existing senders`);

    // Show statistics by category
    const categoryStats = await sql`
      SELECT
        category,
        COUNT(*) as count,
        ROUND(AVG(trust_score)::numeric, 1) as avg_trust_score,
        MIN(trust_score) as min_trust_score,
        MAX(trust_score) as max_trust_score
      FROM sender_reputation
      GROUP BY category
      ORDER BY avg_trust_score DESC
    `;

    console.log('\n📊 Statistics by category:');
    console.log('Category          | Count | Avg Trust | Min | Max');
    console.log('------------------|-------|-----------|-----|-----');
    categoryStats.forEach((row: any) => {
      console.log(
        `${row.category.padEnd(17)} | ${String(row.count).padStart(5)} | ${String(row.avg_trust_score).padStart(9)} | ${String(row.min_trust_score).padStart(3)} | ${String(row.max_trust_score).padStart(3)}`
      );
    });

    // Show total count
    const [totalResult] = await sql`
      SELECT COUNT(*) as total FROM sender_reputation
    `;

    console.log(`\n📈 Total trusted senders in database: ${totalResult.total}`);

    // Show examples of highest trust scores
    const topSenders = await sql`
      SELECT domain, display_name, category, trust_score
      FROM sender_reputation
      ORDER BY trust_score DESC, domain ASC
      LIMIT 10
    `;

    console.log('\n🏆 Top 10 most trusted senders:');
    topSenders.forEach((row: any, idx: number) => {
      console.log(`  ${idx + 1}. ${row.display_name} (${row.domain}) - Score: ${row.trust_score} [${row.category}]`);
    });

  } catch (error) {
    console.error('\n❌ Seeding failed:', error);
    throw error;
  }
}

seedSenderReputation().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
