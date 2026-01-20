/**
 * Run Migration 009: Consolidate tenant_id columns to VARCHAR(255)
 *
 * Usage:
 *   DATABASE_URL="postgresql://..." npx tsx scripts/run-migration-009.ts
 */

import { neon } from '@neondatabase/serverless';
import fs from 'fs';
import path from 'path';

async function runMigration009() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    console.error('❌ DATABASE_URL is not set');
    console.log('\nUsage:');
    console.log('  DATABASE_URL="postgresql://..." npx tsx scripts/run-migration-009.ts');
    process.exit(1);
  }

  console.log('🔗 Connecting to database...');
  const sql = neon(databaseUrl);

  try {
    // Read migration file
    const migrationPath = path.join(__dirname, '../lib/db/migrations/009_consolidate_tenant_id.sql');
    const migrationSql = fs.readFileSync(migrationPath, 'utf8');

    console.log('📋 Running Migration 009: Consolidate tenant_id columns...\n');

    // Split by DO $$ blocks and regular statements
    // This migration uses PL/pgSQL blocks that need special handling
    const blocks = migrationSql.split(/(?=DO \$\$)/);

    let executedCount = 0;

    for (const block of blocks) {
      const trimmed = block.trim();
      if (!trimmed || trimmed.startsWith('--')) continue;

      // Handle DO $$ blocks
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

          // Handle any remaining statements after the DO block
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
        // Regular statements (CREATE INDEX, etc.)
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

    console.log(`\n\n✅ Migration 009 complete! (${executedCount} statements executed)`);

    // Verify tenant_id types
    console.log('\n📊 Verifying tenant_id column types...\n');

    const results = await sql`
      SELECT table_name, column_name, data_type, udt_name
      FROM information_schema.columns
      WHERE column_name = 'tenant_id'
        AND table_schema = 'public'
      ORDER BY table_name;
    `;

    console.log('Table                    | Type');
    console.log('-------------------------|------------------');
    for (const row of results) {
      const tableName = (row.table_name as string).padEnd(24);
      const type = row.udt_name || row.data_type;
      const status = type === 'uuid' ? '❌ UUID (needs fix)' : '✅ ' + type;
      console.log(`${tableName} | ${status}`);
    }

    // Check for remaining FK constraints
    const fkResults = await sql`
      SELECT tc.table_name, tc.constraint_name
      FROM information_schema.table_constraints AS tc
      JOIN information_schema.constraint_column_usage AS ccu
        ON ccu.constraint_name = tc.constraint_name
      WHERE tc.constraint_type = 'FOREIGN KEY'
        AND ccu.table_name = 'tenants'
        AND ccu.column_name = 'id';
    `;

    if (fkResults.length > 0) {
      console.log('\n⚠️  Remaining FK constraints to tenants table:');
      for (const row of fkResults) {
        console.log(`  - ${row.table_name}: ${row.constraint_name}`);
      }
    } else {
      console.log('\n✅ No remaining FK constraints to tenants table');
    }

  } catch (error) {
    console.error('\n❌ Migration failed:', error);
    process.exit(1);
  }
}

runMigration009();
