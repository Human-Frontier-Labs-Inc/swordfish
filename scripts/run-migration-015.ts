import { neon } from '@neondatabase/serverless';
import * as fs from 'fs';
import * as path from 'path';

async function runMigration015() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    console.error('❌ DATABASE_URL environment variable is required');
    console.error('Usage: DATABASE_URL="postgresql://..." npx tsx scripts/run-migration-015.ts');
    process.exit(1);
  }

  console.log('🚀 Running migration 015: Sender Reputation System');
  console.log('📊 Database:', databaseUrl.split('@')[1]?.split('/')[0] || 'unknown');

  const sql = neon(databaseUrl);

  try {
    // Read migration SQL
    const migrationPath = path.join(process.cwd(), 'lib/db/migrations/015_sender_reputation.sql');
    const migrationSQL = fs.readFileSync(migrationPath, 'utf-8');

    // Split by semicolon and filter out empty statements
    const statements = migrationSQL
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));

    console.log(`📝 Executing ${statements.length} SQL statements...`);

    let executedCount = 0;
    for (const statement of statements) {
      await sql.query(statement + ';');
      executedCount++;
      console.log(`  ✓ Statement ${executedCount}/${statements.length} executed`);
    }

    // Verify tables created
    const tablesResult = await sql`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name IN ('sender_reputation', 'email_feedback')
      ORDER BY table_name
    `;

    console.log('\n📋 Tables created:');
    tablesResult.forEach((row: any) => {
      console.log(`  ✓ ${row.table_name}`);
    });

    // Verify indexes created
    const indexesResult = await sql`
      SELECT indexname
      FROM pg_indexes
      WHERE schemaname = 'public'
        AND tablename IN ('sender_reputation', 'email_feedback')
      ORDER BY indexname
    `;

    console.log('\n🔍 Indexes created:');
    indexesResult.forEach((row: any) => {
      console.log(`  ✓ ${row.indexname}`);
    });

    console.log(`\n✅ Migration 015 complete! (${executedCount} statements executed)`);
  } catch (error) {
    console.error('\n❌ Migration failed:', error);
    throw error;
  }
}

runMigration015().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
