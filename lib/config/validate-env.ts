/**
 * Environment Variable Validation
 *
 * Validates that critical environment variables are present on startup.
 * Logs warnings for missing optional variables. Does not throw — the app
 * should still start for development environments.
 */

const REQUIRED_ENV_VARS = [
  'DATABASE_URL',
  'CLERK_SECRET_KEY',
  'NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY',
] as const;

const OPTIONAL_ENV_VARS = [
  'ANTHROPIC_API_KEY',
  'STRIPE_SECRET_KEY',
  'UPSTASH_REDIS_REST_URL',
] as const;

export function validateEnvironment(): void {
  const missingRequired: string[] = [];
  const missingOptional: string[] = [];

  for (const envVar of REQUIRED_ENV_VARS) {
    if (!process.env[envVar]) {
      missingRequired.push(envVar);
    }
  }

  for (const envVar of OPTIONAL_ENV_VARS) {
    if (!process.env[envVar]) {
      missingOptional.push(envVar);
    }
  }

  if (missingRequired.length > 0) {
    console.error(
      `[swordfish] CRITICAL: Missing required environment variables: ${missingRequired.join(', ')}`
    );
  }

  if (missingOptional.length > 0) {
    console.warn(
      `[swordfish] WARNING: Missing optional environment variables: ${missingOptional.join(', ')}. Some features may be unavailable.`
    );
  }

  if (missingRequired.length === 0 && missingOptional.length === 0) {
    console.info('[swordfish] All environment variables validated successfully.');
  }
}
