import { neon, NeonQueryFunction } from '@neondatabase/serverless';
import fs from 'fs';
import path from 'path';

async function migrate() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    console.error('DATABASE_URL is not set');
    process.exit(1);
  }

  console.log('Connecting to Neon database...');
  const sql: NeonQueryFunction<false, false> = neon(databaseUrl);

  try {
    // Read schema file
    const schemaPath = path.join(__dirname, '../lib/db/schema.sql');
    const schema = fs.readFileSync(schemaPath, 'utf8');

    console.log('Applying schema...');

    // Split by semicolons and execute each statement
    const statements = schema
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));

    for (const statement of statements) {
      try {
        // Use unsafe raw query for dynamic SQL (schema migration only)
        await sql.transaction([sql`SELECT 1`]); // Dummy to ensure connection
        await sql([statement + ';'] as unknown as TemplateStringsArray);
        console.log('✓ Executed statement');
      } catch (err: unknown) {
        const error = err as Error;
        // Ignore "already exists" errors
        if (!error.message?.includes('already exists')) {
          console.error('Error:', error.message);
        }
      }
    }

    console.log('\n✅ Schema migration complete!');

    // Verify tables exist
    const tables = await sql`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
      ORDER BY table_name;
    `;

    console.log('\nTables created:');
    for (const row of tables) {
      console.log(`  - ${row.table_name}`);
    }
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

migrate();
