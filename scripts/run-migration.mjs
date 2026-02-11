/**
 * Run SQL migration using Neon serverless driver
 * Usage: node scripts/run-migration.mjs <migration-file> [database-url]
 */

import { neon } from '@neondatabase/serverless';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const DATABASE_URL = process.env.DATABASE_URL || process.argv[3];
const migrationFile = process.argv[2];

if (!migrationFile) {
  console.error('Usage: node scripts/run-migration.mjs <migration-file> [database-url]');
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error('DATABASE_URL environment variable or third argument required');
  process.exit(1);
}

async function runMigration() {
  const sql = neon(DATABASE_URL);
  
  console.log(`Reading migration file: ${migrationFile}`);
  const migrationPath = resolve(process.cwd(), migrationFile);
  const migrationSQL = readFileSync(migrationPath, 'utf-8');
  
  // Split by semicolons but handle $$ blocks (plpgsql functions)
  const statements = splitSQLStatements(migrationSQL);
  
  console.log(`Found ${statements.length} statements to execute`);
  
  let successCount = 0;
  let errorCount = 0;
  
  for (let i = 0; i < statements.length; i++) {
    const stmt = statements[i].trim();
    if (!stmt) continue;
    
    try {
      // Use sql.query() for raw SQL execution
      await sql.query(stmt, []);
      successCount++;
      // Show progress every 5 statements
      if (successCount % 5 === 0) {
        console.log(`✓ Executed ${successCount} statements...`);
      }
    } catch (error) {
      errorCount++;
      console.error(`✗ Statement ${i + 1} failed:`, error.message);
      // Show the first 200 chars of the statement
      console.error(`  Statement: ${stmt.substring(0, 200)}...`);
    }
  }
  
  console.log(`\nMigration complete: ${successCount} succeeded, ${errorCount} failed`);
}

/**
 * Split SQL into statements, handling $$ blocks
 */
function splitSQLStatements(sql) {
  const statements = [];
  let current = '';
  let inDollarQuote = false;
  let dollarTag = '';
  
  const lines = sql.split('\n');
  
  for (const line of lines) {
    // Skip pure comment lines (but keep them if inside $$ block)
    if (line.trim().startsWith('--') && !inDollarQuote) {
      continue;
    }
    
    current += line + '\n';
    
    // Check for $$ or $tag$ (plpgsql function delimiters)
    const dollarMatches = line.match(/\$[^$]*\$/g);
    if (dollarMatches) {
      for (const match of dollarMatches) {
        if (!inDollarQuote) {
          inDollarQuote = true;
          dollarTag = match;
        } else if (match === dollarTag) {
          inDollarQuote = false;
          dollarTag = '';
        }
      }
    }
    
    // If we're not in a $$ block and line ends with ;, it's end of statement
    if (!inDollarQuote && line.trim().endsWith(';')) {
      const trimmed = current.trim();
      if (trimmed && !trimmed.match(/^--/)) {
        statements.push(trimmed);
      }
      current = '';
    }
  }
  
  // Add any remaining content
  if (current.trim() && !current.trim().match(/^--/)) {
    statements.push(current.trim());
  }
  
  return statements;
}

runMigration().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});
