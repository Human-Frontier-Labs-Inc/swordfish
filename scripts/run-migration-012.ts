/**
 * Run Migration 012: Fix scheduled_reports schema
 *
 * Usage:
 *   DATABASE_URL="postgresql://..." npx tsx scripts/run-migration-012.ts
 */

import { neon } from '@neondatabase/serverless';

async function runMigration012() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    console.error('❌ DATABASE_URL is not set');
    console.log('\nUsage:');
    console.log('  DATABASE_URL="postgresql://..." npx tsx scripts/run-migration-012.ts');
    process.exit(1);
  }

  console.log('🔗 Connecting to database...');
  const sql = neon(databaseUrl);

  try {
    console.log('📋 Running Migration 012: Fix scheduled_reports schema...\n');

    // Step 1: Add frequency column if it doesn't exist
    console.log('Adding frequency column...');
    try {
      await sql`ALTER TABLE scheduled_reports ADD COLUMN IF NOT EXISTS frequency TEXT`;
      console.log('✓ frequency column added/exists');
    } catch (err: unknown) {
      const error = err as Error;
      if (!error.message?.includes('already exists')) {
        console.error('⚠️  Warning:', error.message);
      } else {
        console.log('✓ frequency column already exists');
      }
    }

    // Step 2: Copy data from schedule to frequency if schedule exists
    console.log('Copying data from schedule to frequency...');
    try {
      await sql`
        UPDATE scheduled_reports
        SET frequency = schedule
        WHERE frequency IS NULL
          AND schedule IS NOT NULL
      `;
      console.log('✓ Data copied from schedule to frequency');
    } catch (err: unknown) {
      const error = err as Error;
      if (!error.message?.includes('does not exist')) {
        console.error('⚠️  Warning:', error.message);
      } else {
        console.log('⏭️  schedule column does not exist, skipping copy');
      }
    }

    // Step 3: Add enabled column if it doesn't exist
    console.log('Adding enabled column...');
    try {
      await sql`ALTER TABLE scheduled_reports ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true`;
      console.log('✓ enabled column added/exists');
    } catch (err: unknown) {
      const error = err as Error;
      if (!error.message?.includes('already exists')) {
        console.error('⚠️  Warning:', error.message);
      } else {
        console.log('✓ enabled column already exists');
      }
    }

    // Step 4: Copy data from is_active to enabled if is_active exists
    console.log('Copying data from is_active to enabled...');
    try {
      await sql`
        UPDATE scheduled_reports
        SET enabled = is_active
        WHERE enabled IS NULL
          AND is_active IS NOT NULL
      `;
      console.log('✓ Data copied from is_active to enabled');
    } catch (err: unknown) {
      const error = err as Error;
      if (!error.message?.includes('does not exist')) {
        console.error('⚠️  Warning:', error.message);
      } else {
        console.log('⏭️  is_active column does not exist, skipping copy');
      }
    }

    // Step 5: Add config column if it doesn't exist
    console.log('Adding config column...');
    try {
      await sql`ALTER TABLE scheduled_reports ADD COLUMN IF NOT EXISTS config JSONB DEFAULT '{}'`;
      console.log('✓ config column added/exists');
    } catch (err: unknown) {
      const error = err as Error;
      if (!error.message?.includes('already exists')) {
        console.error('⚠️  Warning:', error.message);
      } else {
        console.log('✓ config column already exists');
      }
    }

    // Step 6: Add created_by column if it doesn't exist
    console.log('Adding created_by column...');
    try {
      await sql`ALTER TABLE scheduled_reports ADD COLUMN IF NOT EXISTS created_by TEXT`;
      console.log('✓ created_by column added/exists');
    } catch (err: unknown) {
      const error = err as Error;
      if (!error.message?.includes('already exists')) {
        console.error('⚠️  Warning:', error.message);
      } else {
        console.log('✓ created_by column already exists');
      }
    }

    // Step 7: Set default value for frequency where NULL
    console.log('Setting default frequency values...');
    try {
      await sql`UPDATE scheduled_reports SET frequency = 'weekly' WHERE frequency IS NULL`;
      console.log('✓ Default frequency values set');
    } catch (err: unknown) {
      console.error('⚠️  Warning:', (err as Error).message);
    }

    // Step 8: Set frequency NOT NULL constraint
    console.log('Adding NOT NULL constraint to frequency...');
    try {
      await sql`ALTER TABLE scheduled_reports ALTER COLUMN frequency SET NOT NULL`;
      console.log('✓ NOT NULL constraint added to frequency');
    } catch (err: unknown) {
      const error = err as Error;
      console.log('⏭️  Could not add NOT NULL (may already exist):', error.message?.substring(0, 50));
    }

    // Step 9: Add check constraint for frequency values
    console.log('Adding check constraint for frequency values...');
    try {
      await sql`ALTER TABLE scheduled_reports DROP CONSTRAINT IF EXISTS scheduled_reports_frequency_check`;
      await sql`ALTER TABLE scheduled_reports ADD CONSTRAINT scheduled_reports_frequency_check CHECK (frequency IN ('daily', 'weekly', 'monthly'))`;
      console.log('✓ Check constraint added for frequency');
    } catch (err: unknown) {
      const error = err as Error;
      console.error('⚠️  Warning:', error.message);
    }

    console.log('\n✅ Migration 012 complete!');

    // Verify scheduled_reports columns
    console.log('\n📊 Verifying scheduled_reports columns...\n');

    const results = await sql`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns
      WHERE table_name = 'scheduled_reports'
        AND table_schema = 'public'
      ORDER BY ordinal_position
    `;

    console.log('Column               | Type         | Nullable | Default');
    console.log('---------------------|--------------|----------|--------');
    for (const row of results) {
      const colName = (row.column_name as string).padEnd(20);
      const dataType = (row.data_type as string).padEnd(12);
      const nullable = (row.is_nullable as string).padEnd(8);
      const defaultVal = (row.column_default as string || 'null').substring(0, 20);
      console.log(`${colName} | ${dataType} | ${nullable} | ${defaultVal}`);
    }

    // Check for frequency column specifically
    const hasFrequency = results.some((r) => r.column_name === 'frequency');
    const hasEnabled = results.some((r) => r.column_name === 'enabled');

    console.log('\n📋 Summary:');
    console.log(`  - frequency column: ${hasFrequency ? '✅ Present' : '❌ Missing'}`);
    console.log(`  - enabled column: ${hasEnabled ? '✅ Present' : '❌ Missing'}`);

  } catch (error) {
    console.error('\n❌ Migration failed:', error);
    process.exit(1);
  }
}

runMigration012();
