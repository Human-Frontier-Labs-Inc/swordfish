/**
 * Run Migration 014: Schema hardening for production readiness
 *
 * Usage:
 *   DATABASE_URL="postgresql://..." npx tsx scripts/run-migration-014.ts
 */

import { neon } from '@neondatabase/serverless';
import fs from 'fs';
import path from 'path';

async function runMigration014() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    console.error('❌ DATABASE_URL is not set');
    console.log('\nUsage:');
    console.log('  DATABASE_URL="postgresql://..." npx tsx scripts/run-migration-014.ts');
    process.exit(1);
  }

  console.log('🔗 Connecting to database...');
  const sql = neon(databaseUrl);

  try {
    const migrationPath = path.join(__dirname, '../lib/db/migrations/014_schema_hardening.sql');
    const migrationSql = fs.readFileSync(migrationPath, 'utf8');

    console.log('📋 Running Migration 014: Schema hardening...\n');

    const blocks = migrationSql.split(/(?=DO \$\$)/);
    let executedCount = 0;

    for (const block of blocks) {
      const trimmed = block.trim();
      if (!trimmed || trimmed.startsWith('--')) continue;

      if (trimmed.startsWith('DO $$')) {
        const endIndex = trimmed.indexOf('END $$;');
        if (endIndex !== -1) {
          const doBlock = trimmed.substring(0, endIndex + 7);
          try {
            await sql(doBlock as unknown as TemplateStringsArray);
            executedCount++;
            process.stdout.write('.');
          } catch (err: unknown) {
            const error = err as Error;
            if (!error.message?.includes('already exists') &&
                !error.message?.includes('does not exist')) {
              console.error('\n⚠️  Warning:', error.message);
            }
          }

          const remaining = trimmed.substring(endIndex + 7).trim();
          if (remaining) {
            const statements = remaining.split(';').filter(s => s.trim() && !s.trim().startsWith('--'));
            for (const stmt of statements) {
              try {
                await sql(stmt.trim() as unknown as TemplateStringsArray);
                executedCount++;
                process.stdout.write('.');
              } catch (err: unknown) {
                const error = err as Error;
                if (!error.message?.includes('already exists')) {
                  console.error('\n⚠️  Warning:', error.message);
                }
              }
            }
          }
        }
      } else {
        const statements = trimmed.split(';').filter(s => s.trim() && !s.trim().startsWith('--'));
        for (const stmt of statements) {
          try {
            await sql(stmt.trim() as unknown as TemplateStringsArray);
            executedCount++;
            process.stdout.write('.');
          } catch (err: unknown) {
            const error = err as Error;
            if (!error.message?.includes('already exists')) {
              console.error('\n⚠️  Warning:', error.message);
            }
          }
        }
      }
    }

    console.log(`\n\n✅ Migration 014 complete! (${executedCount} statements executed)`);

    console.log('\n📊 Verifying updated columns...\n');

    const columns = await sql`
      SELECT table_name, column_name, data_type, character_maximum_length
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND (
          (table_name = 'notifications' AND column_name IN ('type', 'resource_type', 'resource_id')) OR
          (table_name = 'audit_log' AND column_name IN ('action', 'resource_type')) OR
          (table_name = 'threats' AND column_name = 'threat_type')
        )
      ORDER BY table_name, column_name;
    `;

    console.log('Table          | Column         | Type        | Length');
    console.log('---------------|----------------|-------------|--------');
    for (const row of columns) {
      const tableName = (row.table_name as string).padEnd(14);
      const colName = (row.column_name as string).padEnd(14);
      const dataType = (row.data_type as string).padEnd(11);
      const length = row.character_maximum_length ?? '';
      console.log(`${tableName} | ${colName} | ${dataType} | ${length}`);
    }
  } catch (error) {
    console.error('\n❌ Migration failed:', error);
    process.exit(1);
  }
}

runMigration014();
