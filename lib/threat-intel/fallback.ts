/**
 * Threat Intelligence Fallback System
 *
 * Provides graceful degradation when external threat intel APIs are unavailable.
 * Uses circuit breaker pattern and cached fallback responses.
 */

import type { UrlCheckResult, DomainCheckResult, IpCheckResult } from './intel-service';

// ============================================================================
// Types
// ============================================================================

export interface FallbackConfig {
  /** Maximum consecutive failures before circuit opens */
  failureThreshold: number;
  /** Time in ms before attempting to close circuit */
  resetTimeout: number;
  /** Whether to use cached results as fallback */
  useCachedFallback: boolean;
  /** Log degraded operations */
  logDegradation: boolean;
}

export interface CircuitState {
  failures: number;
  lastFailure: number;
  state: 'closed' | 'open' | 'half-open';
  lastSuccess: number;
}

export interface FallbackResult<T> {
  data: T;
  fromFallback: boolean;
  degraded: boolean;
  reason?: string;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_FALLBACK_CONFIG: FallbackConfig = {
  failureThreshold: 3,
  resetTimeout: 60000, // 1 minute
  useCachedFallback: true,
  logDegradation: true,
};

// ============================================================================
// Circuit Breaker Implementation
// ============================================================================

const circuitStates = new Map<string, CircuitState>();

/**
 * Get or initialize circuit state for a service
 */
function getCircuitState(serviceName: string): CircuitState {
  if (!circuitStates.has(serviceName)) {
    circuitStates.set(serviceName, {
      failures: 0,
      lastFailure: 0,
      state: 'closed',
      lastSuccess: Date.now(),
    });
  }
  return circuitStates.get(serviceName)!;
}

/**
 * Record a successful call
 */
export function recordSuccess(serviceName: string): void {
  const state = getCircuitState(serviceName);
  state.failures = 0;
  state.state = 'closed';
  state.lastSuccess = Date.now();
}

/**
 * Record a failed call
 */
export function recordFailure(serviceName: string, config: FallbackConfig = DEFAULT_FALLBACK_CONFIG): void {
  const state = getCircuitState(serviceName);
  state.failures++;
  state.lastFailure = Date.now();

  if (state.failures >= config.failureThreshold) {
    state.state = 'open';
    if (config.logDegradation) {
      console.warn(`[threat-intel-fallback] Circuit OPEN for ${serviceName} after ${state.failures} failures`);
    }
  }
}

/**
 * Check if circuit allows requests
 */
export function isCircuitOpen(serviceName: string, config: FallbackConfig = DEFAULT_FALLBACK_CONFIG): boolean {
  const state = getCircuitState(serviceName);

  if (state.state === 'closed') {
    return false;
  }

  // Check if reset timeout has passed
  const timeSinceFailure = Date.now() - state.lastFailure;
  if (timeSinceFailure >= config.resetTimeout) {
    state.state = 'half-open';
    if (config.logDegradation) {
      console.info(`[threat-intel-fallback] Circuit HALF-OPEN for ${serviceName}, allowing test request`);
    }
    return false;
  }

  return true;
}

/**
 * Get circuit status for monitoring
 */
export function getCircuitStatus(serviceName: string): CircuitState {
  return { ...getCircuitState(serviceName) };
}

/**
 * Reset circuit state (for testing)
 */
export function resetCircuit(serviceName: string): void {
  circuitStates.delete(serviceName);
}

/**
 * Get all circuit statuses
 */
export function getAllCircuitStatuses(): Record<string, CircuitState> {
  const statuses: Record<string, CircuitState> = {};
  circuitStates.forEach((state, name) => {
    statuses[name] = { ...state };
  });
  return statuses;
}

// ============================================================================
// Default Fallback Responses
// ============================================================================

/**
 * Default URL check result when APIs are unavailable
 * SECURITY: Returns UNKNOWN status, not SAFE - we cannot verify safety when APIs fail
 */
export function getDefaultUrlCheckResult(url: string): UrlCheckResult {
  // SECURITY FIX: Do NOT return isMalicious: false when we can't verify
  // Instead, use a neutral score and flag as unverified
  return {
    url,
    isMalicious: false, // Keep for backward compat but see riskScore
    threatTypes: ['unverified'], // Flag as unverified
    riskScore: 50, // CHANGED from 0: Neutral score indicates unknown, not safe
    lastSeen: undefined,
    sources: ['fallback_unverified'], // Clearly mark as fallback
  };
}

/**
 * Default domain check result when APIs are unavailable
 * SECURITY: Returns UNKNOWN status - we cannot verify reputation when APIs fail
 */
export function getDefaultDomainCheckResult(domain: string): DomainCheckResult {
  return {
    domain,
    isSuspicious: false, // Keep for backward compat
    reputationScore: 50, // Neutral score indicates unknown
    categories: ['unverified'], // SECURITY FIX: Flag as unverified
    registrar: undefined,
    ageDays: -1, // CHANGED from 0: -1 indicates unknown age (0 could be valid for new domains)
  };
}

/**
 * Default IP check result when APIs are unavailable
 * SECURITY: Returns UNKNOWN status - we cannot verify IP reputation when APIs fail
 */
export function getDefaultIpCheckResult(ip: string): IpCheckResult {
  // SECURITY FIX: Use neutral/unknown values instead of "safe" values
  return {
    ip,
    isProxy: false, // Keep for backward compat
    isTor: false, // Keep for backward compat
    isDatacenter: false, // Keep for backward compat
    abuseConfidence: 50, // CHANGED from 0: Neutral score indicates unknown, not safe
    country: 'UNVERIFIED', // SECURITY FIX: Flag as unverified instead of undefined
  };
}

// ============================================================================
// Fallback-Aware Execution
// ============================================================================

/**
 * Execute a function with circuit breaker and fallback
 */
export async function executeWithFallback<T>(
  serviceName: string,
  operation: () => Promise<T>,
  fallbackFn: () => T,
  config: FallbackConfig = DEFAULT_FALLBACK_CONFIG
): Promise<FallbackResult<T>> {
  // Check if circuit is open
  if (isCircuitOpen(serviceName, config)) {
    if (config.logDegradation) {
      console.warn(`[threat-intel-fallback] ${serviceName} circuit open, using fallback`);
    }
    return {
      data: fallbackFn(),
      fromFallback: true,
      degraded: true,
      reason: 'circuit_open',
    };
  }

  try {
    const result = await operation();
    recordSuccess(serviceName);
    return {
      data: result,
      fromFallback: false,
      degraded: false,
    };
  } catch (error) {
    recordFailure(serviceName, config);

    if (config.logDegradation) {
      console.warn(
        `[threat-intel-fallback] ${serviceName} failed: ${error instanceof Error ? error.message : 'Unknown error'}, using fallback`
      );
    }

    return {
      data: fallbackFn(),
      fromFallback: true,
      degraded: true,
      reason: error instanceof Error ? error.message : 'unknown_error',
    };
  }
}

/**
 * Execute multiple operations with fallback, returning partial results
 */
export async function executeMultipleWithFallback<T>(
  operations: Array<{
    serviceName: string;
    operation: () => Promise<T>;
    fallbackFn: () => T;
  }>,
  config: FallbackConfig = DEFAULT_FALLBACK_CONFIG
): Promise<Array<FallbackResult<T>>> {
  return Promise.all(
    operations.map(({ serviceName, operation, fallbackFn }) =>
      executeWithFallback(serviceName, operation, fallbackFn, config)
    )
  );
}

// ============================================================================
// Health Check
// ============================================================================

export interface ServiceHealth {
  serviceName: string;
  healthy: boolean;
  circuitState: 'closed' | 'open' | 'half-open';
  consecutiveFailures: number;
  lastSuccess: Date | null;
  lastFailure: Date | null;
}

/**
 * Get health status for all threat intel services
 */
export function getThreatIntelHealth(): ServiceHealth[] {
  const services = ['virustotal', 'urlscan', 'threat-intel-service', 'domain-age', 'ip-blocklist', 'whois'];

  return services.map((serviceName) => {
    const state = getCircuitState(serviceName);
    return {
      serviceName,
      healthy: state.state === 'closed',
      circuitState: state.state,
      consecutiveFailures: state.failures,
      lastSuccess: state.lastSuccess > 0 ? new Date(state.lastSuccess) : null,
      lastFailure: state.lastFailure > 0 ? new Date(state.lastFailure) : null,
    };
  });
}

/**
 * Check if threat intel system is degraded
 */
export function isThreatIntelDegraded(): boolean {
  const health = getThreatIntelHealth();
  return health.some((s) => s.circuitState !== 'closed');
}

/**
 * Get degraded services list
 */
export function getDegradedServices(): string[] {
  const health = getThreatIntelHealth();
  return health.filter((s) => s.circuitState !== 'closed').map((s) => s.serviceName);
}
