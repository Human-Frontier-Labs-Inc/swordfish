/**
 * Feature Flags System
 *
 * Provides feature flag management with support for percentage rollouts,
 * targeting rules, overrides, and audit logging.
 */

export enum RolloutStrategy {
  ALL = 'all',
  NONE = 'none',
  PERCENTAGE = 'percentage',
  GRADUAL = 'gradual',
}

export interface FlagVariant {
  key: string;
  value: FlagValue;
}

export interface TargetingRule {
  attribute: string;
  operator: 'equals' | 'notEquals' | 'in' | 'notIn' | 'contains' | 'startsWith';
  value: unknown;
}

export interface TargetingConfig {
  rules?: TargetingRule[];
  matchAll?: boolean;
  tenants?: {
    include?: string[];
    exclude?: string[];
  };
  users?: {
    include?: string[];
    exclude?: string[];
  };
}

export interface RolloutConfig {
  strategy: RolloutStrategy;
  percentage?: number;
  startTime?: number;
  endTime?: number;
  startPercentage?: number;
  endPercentage?: number;
}

export interface Flag {
  key: string;
  name: string;
  description?: string;
  enabled: boolean;
  variants?: FlagVariant[];
  defaultVariant?: string;
  rollout?: RolloutConfig;
  targeting?: TargetingConfig;
}

export type FlagValue = boolean | string | number | Record<string, unknown> | null;

export interface EvaluationContext {
  userId?: string;
  tenantId?: string;
  plan?: string;
  country?: string;
  [key: string]: unknown;
}

export interface FlagOverride {
  flagKey: string;
  userId?: string;
  tenantId?: string;
  enabled: boolean;
  value?: FlagValue;
}

export interface FlagAuditLog {
  flagKey: string;
  action: 'evaluate' | 'update' | 'create' | 'delete' | 'override';
  timestamp: Date;
  actor?: string;
  context?: EvaluationContext;
  result?: boolean;
  changes?: Record<string, unknown>;
}

export interface FeatureFlagConfig {
  defaultEnabled?: boolean;
  cacheTtl?: number;
  auditLog?: boolean;
  maxAuditLogs?: number;
}

export interface FlagChangeEvent {
  key: string;
  previousValue: Flag;
  newValue: Flag;
}

export interface ExportedConfig {
  version: string;
  flags: Flag[];
  overrides?: FlagOverride[];
}

type EventHandler = (event: FlagChangeEvent) => void;

/**
 * Feature Flags implementation
 */
export class FeatureFlags {
  private config: Required<FeatureFlagConfig>;
  private flags: Map<string, Flag> = new Map();
  private overrides: FlagOverride[] = [];
  private auditLogs: FlagAuditLog[] = [];
  private cache: Map<string, { result: boolean; timestamp: number }> = new Map();
  private eventHandlers: Map<string, EventHandler[]> = new Map();

  constructor(config: FeatureFlagConfig = {}) {
    this.config = {
      defaultEnabled: config.defaultEnabled ?? false,
      cacheTtl: config.cacheTtl ?? 0,
      auditLog: config.auditLog ?? false,
      maxAuditLogs: config.maxAuditLogs ?? 1000,
    };
  }

  getConfig(): FeatureFlagConfig {
    return {
      defaultEnabled: this.config.defaultEnabled,
      cacheTtl: this.config.cacheTtl,
      auditLog: this.config.auditLog,
    };
  }

  define(flag: Flag): void {
    if (this.flags.has(flag.key)) {
      throw new Error('Flag already defined');
    }
    this.flags.set(flag.key, { ...flag });
    this.logAction(flag.key, 'create');
  }

  getFlag(key: string): Flag | undefined {
    const flag = this.flags.get(key);
    return flag ? { ...flag } : undefined;
  }

  listFlags(): Flag[] {
    return Array.from(this.flags.values()).map(f => ({ ...f }));
  }

  update(
    key: string,
    updates: Partial<Flag>,
    options: { actor?: string; invalidateCache?: boolean } = {}
  ): void {
    const flag = this.flags.get(key);
    if (!flag) return;

    const previousValue = { ...flag };
    Object.assign(flag, updates);

    if (options.invalidateCache) {
      this.invalidateCacheForFlag(key);
    }

    this.logAction(key, 'update', options.actor, undefined, undefined, updates);

    this.emit('change', {
      key,
      previousValue,
      newValue: { ...flag },
    });
  }

  delete(key: string): void {
    this.flags.delete(key);
    this.invalidateCacheForFlag(key);
    this.logAction(key, 'delete');
  }

  isEnabled(key: string, context: EvaluationContext = {}): boolean {
    // Check cache first
    const cacheKey = this.getCacheKey(key, context);
    if (this.config.cacheTtl > 0) {
      const cached = this.cache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.config.cacheTtl) {
        return cached.result;
      }
    }

    const result = this.evaluate(key, context);

    // Update cache
    if (this.config.cacheTtl > 0) {
      this.cache.set(cacheKey, { result, timestamp: Date.now() });
    }

    this.logAction(key, 'evaluate', undefined, context, result);

    return result;
  }

  getValue(key: string, context: EvaluationContext = {}): FlagValue {
    const flag = this.flags.get(key);
    if (!flag || !flag.variants || flag.variants.length === 0) {
      return this.isEnabled(key, context);
    }

    if (!this.isEnabled(key, context)) {
      return null;
    }

    // Select variant based on user hash
    const userId = context.userId || 'anonymous';
    const hash = this.hashString(`${key}:${userId}`);
    const variantIndex = hash % flag.variants.length;

    return flag.variants[variantIndex].value;
  }

  setOverride(override: FlagOverride): void {
    // Remove existing override for same scope
    this.overrides = this.overrides.filter(o => {
      if (o.flagKey !== override.flagKey) return true;
      if (override.userId && o.userId === override.userId) return false;
      if (override.tenantId && !override.userId && o.tenantId === override.tenantId && !o.userId) return false;
      if (!override.userId && !override.tenantId && !o.userId && !o.tenantId) return false;
      return true;
    });

    this.overrides.push(override);
    this.invalidateCacheForFlag(override.flagKey);
    this.logAction(override.flagKey, 'override');
  }

  removeOverride(flagKey: string, scope: { userId?: string; tenantId?: string }): void {
    this.overrides = this.overrides.filter(o => {
      if (o.flagKey !== flagKey) return true;
      if (scope.userId && o.userId === scope.userId) return false;
      if (scope.tenantId && !scope.userId && o.tenantId === scope.tenantId) return false;
      return true;
    });
    this.invalidateCacheForFlag(flagKey);
  }

  getOverrides(flagKey: string): FlagOverride[] {
    return this.overrides.filter(o => o.flagKey === flagKey);
  }

  getAuditLogs(flagKey?: string): FlagAuditLog[] {
    let logs = flagKey
      ? this.auditLogs.filter(l => l.flagKey === flagKey)
      : [...this.auditLogs];
    // Return newest first
    return logs.reverse();
  }

  on(event: string, handler: EventHandler): void {
    const handlers = this.eventHandlers.get(event) || [];
    handlers.push(handler);
    this.eventHandlers.set(event, handlers);
  }

  off(event: string, handler: EventHandler): void {
    const handlers = this.eventHandlers.get(event) || [];
    const index = handlers.indexOf(handler);
    if (index >= 0) {
      handlers.splice(index, 1);
    }
  }

  export(): ExportedConfig {
    return {
      version: '1.0.0',
      flags: this.listFlags(),
      overrides: [...this.overrides],
    };
  }

  import(config: ExportedConfig): void {
    for (const flag of config.flags) {
      if (!this.flags.has(flag.key)) {
        this.define(flag);
      }
    }
    if (config.overrides) {
      for (const override of config.overrides) {
        this.setOverride(override);
      }
    }
  }

  private evaluate(key: string, context: EvaluationContext): boolean {
    const flag = this.flags.get(key);
    if (!flag) {
      return this.config.defaultEnabled;
    }

    // Check overrides FIRST (highest priority, can override even disabled flags)
    const override = this.findOverride(key, context);
    if (override !== undefined) {
      return override;
    }

    if (!flag.enabled) {
      return false;
    }

    // Check targeting rules
    if (flag.targeting) {
      const targetingResult = this.evaluateTargeting(flag.targeting, context);
      if (!targetingResult) {
        return false;
      }
    }

    // Check rollout strategy
    if (flag.rollout) {
      return this.evaluateRollout(flag.rollout, key, context);
    }

    return true;
  }

  private findOverride(flagKey: string, context: EvaluationContext): boolean | undefined {
    // User override (highest priority)
    if (context.userId) {
      const userOverride = this.overrides.find(
        o => o.flagKey === flagKey && o.userId === context.userId
      );
      if (userOverride) return userOverride.enabled;
    }

    // Tenant override
    if (context.tenantId) {
      const tenantOverride = this.overrides.find(
        o => o.flagKey === flagKey && o.tenantId === context.tenantId && !o.userId
      );
      if (tenantOverride) return tenantOverride.enabled;
    }

    // Global override
    const globalOverride = this.overrides.find(
      o => o.flagKey === flagKey && !o.userId && !o.tenantId
    );
    if (globalOverride) return globalOverride.enabled;

    return undefined;
  }

  private evaluateTargeting(targeting: TargetingConfig, context: EvaluationContext): boolean {
    // Check tenant targeting
    if (targeting.tenants) {
      if (!context.tenantId) return false;

      if (targeting.tenants.exclude?.includes(context.tenantId)) {
        return false;
      }

      if (targeting.tenants.include && !targeting.tenants.include.includes(context.tenantId)) {
        return false;
      }
    }

    // Check user targeting
    if (targeting.users) {
      if (!context.userId) return false;

      if (targeting.users.exclude?.includes(context.userId)) {
        return false;
      }

      if (targeting.users.include && !targeting.users.include.includes(context.userId)) {
        return false;
      }
    }

    // Check attribute rules
    if (targeting.rules && targeting.rules.length > 0) {
      const results = targeting.rules.map(rule => this.evaluateRule(rule, context));

      if (targeting.matchAll) {
        return results.every(r => r);
      } else {
        return results.some(r => r);
      }
    }

    return true;
  }

  private evaluateRule(rule: TargetingRule, context: EvaluationContext): boolean {
    const contextValue = context[rule.attribute];

    switch (rule.operator) {
      case 'equals':
        return contextValue === rule.value;
      case 'notEquals':
        return contextValue !== rule.value;
      case 'in':
        return Array.isArray(rule.value) && rule.value.includes(contextValue);
      case 'notIn':
        return Array.isArray(rule.value) && !rule.value.includes(contextValue);
      case 'contains':
        return typeof contextValue === 'string' && contextValue.includes(String(rule.value));
      case 'startsWith':
        return typeof contextValue === 'string' && contextValue.startsWith(String(rule.value));
      default:
        return false;
    }
  }

  private evaluateRollout(rollout: RolloutConfig, flagKey: string, context: EvaluationContext): boolean {
    switch (rollout.strategy) {
      case RolloutStrategy.ALL:
        return true;

      case RolloutStrategy.NONE:
        return false;

      case RolloutStrategy.PERCENTAGE:
        return this.evaluatePercentage(rollout.percentage || 0, flagKey, context);

      case RolloutStrategy.GRADUAL:
        return this.evaluateGradual(rollout, flagKey, context);

      default:
        return true;
    }
  }

  private evaluatePercentage(percentage: number, flagKey: string, context: EvaluationContext): boolean {
    const userId = context.userId || 'anonymous';
    const hash = this.hashString(`${flagKey}:${userId}`);
    const bucket = hash % 100;
    return bucket < percentage;
  }

  private evaluateGradual(rollout: RolloutConfig, flagKey: string, context: EvaluationContext): boolean {
    if (!rollout.startTime || !rollout.endTime) {
      return false;
    }

    const now = Date.now();
    const startPct = rollout.startPercentage ?? 0;
    const endPct = rollout.endPercentage ?? 100;

    if (now <= rollout.startTime) {
      return this.evaluatePercentage(startPct, flagKey, context);
    }

    if (now >= rollout.endTime) {
      return this.evaluatePercentage(endPct, flagKey, context);
    }

    // Linear interpolation
    const progress = (now - rollout.startTime) / (rollout.endTime - rollout.startTime);
    const currentPct = startPct + progress * (endPct - startPct);

    return this.evaluatePercentage(currentPct, flagKey, context);
  }

  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }

  private getCacheKey(flagKey: string, context: EvaluationContext): string {
    return `${flagKey}:${context.userId || ''}:${context.tenantId || ''}`;
  }

  private invalidateCacheForFlag(flagKey: string): void {
    for (const key of this.cache.keys()) {
      if (key.startsWith(`${flagKey}:`)) {
        this.cache.delete(key);
      }
    }
  }

  private logAction(
    flagKey: string,
    action: FlagAuditLog['action'],
    actor?: string,
    context?: EvaluationContext,
    result?: boolean,
    changes?: Record<string, unknown>
  ): void {
    if (!this.config.auditLog) return;

    this.auditLogs.push({
      flagKey,
      action,
      timestamp: new Date(),
      actor,
      context,
      result,
      changes,
    });

    // Trim logs if over max
    while (this.auditLogs.length > this.config.maxAuditLogs) {
      this.auditLogs.shift();
    }
  }

  private emit(event: string, data: FlagChangeEvent): void {
    const handlers = this.eventHandlers.get(event) || [];
    for (const handler of handlers) {
      try {
        handler(data);
      } catch {
        // Don't let handler errors affect the system
      }
    }
  }
}
