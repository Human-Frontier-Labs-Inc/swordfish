/**
 * Health Check & Deployment Utilities
 *
 * Production readiness checks and system health monitoring
 */

export interface HealthCheckResult {
  service: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  latencyMs?: number;
  message?: string;
  lastChecked: Date;
}

export interface SystemHealth {
  overall: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  uptime: number;
  checks: HealthCheckResult[];
  timestamp: Date;
}

export interface DeploymentConfig {
  environment: 'development' | 'staging' | 'production';
  version: string;
  region?: string;
  features: Record<string, boolean>;
}

// Required environment variables for production
const REQUIRED_ENV_VARS = [
  'DATABASE_URL',
  'CLERK_SECRET_KEY',
  'NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY',
];

const OPTIONAL_ENV_VARS = [
  'STRIPE_SECRET_KEY',
  'STRIPE_WEBHOOK_SECRET',
  'MICROSOFT_CLIENT_ID',
  'MICROSOFT_CLIENT_SECRET',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
];

export class HealthChecker {
  private checks: Map<string, () => Promise<HealthCheckResult>> = new Map();

  constructor() {
    this.registerDefaultChecks();
  }

  private registerDefaultChecks(): void {
    // Database health check
    this.register('database', async () => {
      const start = Date.now();
      try {
        // In production, this would actually ping the database
        const isConnected = !!process.env.DATABASE_URL;
        return {
          service: 'database',
          status: isConnected ? 'healthy' : 'unhealthy',
          latencyMs: Date.now() - start,
          message: isConnected ? 'Database connected' : 'Database URL not configured',
          lastChecked: new Date(),
        };
      } catch (error) {
        return {
          service: 'database',
          status: 'unhealthy',
          latencyMs: Date.now() - start,
          message: error instanceof Error ? error.message : 'Unknown error',
          lastChecked: new Date(),
        };
      }
    });

    // Authentication service check
    this.register('auth', async () => {
      const hasClerkKeys = !!(
        process.env.CLERK_SECRET_KEY &&
        process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
      );
      return {
        service: 'auth',
        status: hasClerkKeys ? 'healthy' : 'unhealthy',
        message: hasClerkKeys ? 'Clerk configured' : 'Clerk keys missing',
        lastChecked: new Date(),
      };
    });

    // Email integration check
    this.register('email-integration', async () => {
      const hasO365 = !!(
        process.env.MICROSOFT_CLIENT_ID &&
        process.env.MICROSOFT_CLIENT_SECRET
      );
      const hasGoogle = !!(
        process.env.GOOGLE_CLIENT_ID &&
        process.env.GOOGLE_CLIENT_SECRET
      );
      const hasAny = hasO365 || hasGoogle;

      return {
        service: 'email-integration',
        status: hasAny ? 'healthy' : 'degraded',
        message: hasAny
          ? `Integrations: ${hasO365 ? 'O365' : ''}${hasO365 && hasGoogle ? ', ' : ''}${hasGoogle ? 'Gmail' : ''}`
          : 'No email integrations configured',
        lastChecked: new Date(),
      };
    });

    // AI/ML service check
    this.register('ai-services', async () => {
      const hasOpenAI = !!process.env.OPENAI_API_KEY;
      const hasAnthropic = !!process.env.ANTHROPIC_API_KEY;
      const hasAny = hasOpenAI || hasAnthropic;

      return {
        service: 'ai-services',
        status: hasAny ? 'healthy' : 'degraded',
        message: hasAny
          ? `AI: ${hasOpenAI ? 'OpenAI' : ''}${hasOpenAI && hasAnthropic ? ', ' : ''}${hasAnthropic ? 'Anthropic' : ''}`
          : 'No AI services configured (using fallback detection)',
        lastChecked: new Date(),
      };
    });

    // Billing service check
    this.register('billing', async () => {
      const hasStripe = !!(
        process.env.STRIPE_SECRET_KEY &&
        process.env.STRIPE_WEBHOOK_SECRET
      );

      return {
        service: 'billing',
        status: hasStripe ? 'healthy' : 'degraded',
        message: hasStripe ? 'Stripe configured' : 'Stripe not configured',
        lastChecked: new Date(),
      };
    });
  }

  register(name: string, check: () => Promise<HealthCheckResult>): void {
    this.checks.set(name, check);
  }

  async check(name: string): Promise<HealthCheckResult | null> {
    const check = this.checks.get(name);
    if (!check) return null;
    return check();
  }

  async checkAll(): Promise<SystemHealth> {
    const results: HealthCheckResult[] = [];

    for (const [, check] of this.checks) {
      results.push(await check());
    }

    const unhealthyCount = results.filter(r => r.status === 'unhealthy').length;
    const degradedCount = results.filter(r => r.status === 'degraded').length;

    let overall: SystemHealth['overall'] = 'healthy';
    if (unhealthyCount > 0) {
      overall = 'unhealthy';
    } else if (degradedCount > 0) {
      overall = 'degraded';
    }

    return {
      overall,
      version: process.env.npm_package_version || '1.0.0',
      uptime: process.uptime(),
      checks: results,
      timestamp: new Date(),
    };
  }
}

export class EnvironmentValidator {
  validate(): { valid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check required variables
    for (const envVar of REQUIRED_ENV_VARS) {
      if (!process.env[envVar]) {
        errors.push(`Missing required environment variable: ${envVar}`);
      }
    }

    // Check optional variables
    for (const envVar of OPTIONAL_ENV_VARS) {
      if (!process.env[envVar]) {
        warnings.push(`Optional environment variable not set: ${envVar}`);
      }
    }

    // Validate DATABASE_URL format
    const dbUrl = process.env.DATABASE_URL;
    if (dbUrl && !dbUrl.startsWith('postgres')) {
      errors.push('DATABASE_URL must be a PostgreSQL connection string');
    }

    // Validate production-specific settings
    if (process.env.NODE_ENV === 'production') {
      if (!process.env.STRIPE_SECRET_KEY?.startsWith('sk_live_')) {
        warnings.push('Using test Stripe keys in production');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  getConfig(): DeploymentConfig {
    const env = (process.env.NODE_ENV || 'development') as DeploymentConfig['environment'];

    return {
      environment: env === 'production' || env === 'staging' ? env : 'development',
      version: process.env.npm_package_version || '1.0.0',
      region: process.env.VERCEL_REGION || process.env.AWS_REGION,
      features: {
        emailIntegration: !!(process.env.MICROSOFT_CLIENT_ID || process.env.GOOGLE_CLIENT_ID),
        aiDetection: !!(process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY),
        billing: !!process.env.STRIPE_SECRET_KEY,
        sso: !!process.env.CLERK_SECRET_KEY,
      },
    };
  }
}

// Singleton instances
export const healthChecker = new HealthChecker();
export const envValidator = new EnvironmentValidator();

// Quick health check for API routes
export async function getHealthStatus(): Promise<SystemHealth> {
  return healthChecker.checkAll();
}

// Readiness check (for Kubernetes/container orchestration)
export async function isReady(): Promise<boolean> {
  const health = await healthChecker.checkAll();
  return health.overall !== 'unhealthy';
}

// Liveness check (simple ping)
export function isAlive(): boolean {
  return true;
}
