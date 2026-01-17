/**
 * Secrets Management System
 *
 * Provides secure secrets storage with encryption, versioning,
 * rotation support, and audit logging.
 */

export enum RotationPolicy {
  NONE = 'none',
  SCHEDULED = 'scheduled',
  ON_DEMAND = 'on_demand',
}

export interface SecretVersion {
  version: number;
  value?: string;
  createdAt: Date;
}

export interface SecretMetadata {
  description?: string;
  owner?: string;
  tags?: string[];
  [key: string]: unknown;
}

export interface RotationConfig {
  policy: RotationPolicy;
  intervalDays?: number;
  lastRotation?: Date;
  nextRotation?: Date;
}

export interface StoredSecret {
  value: string;
  version: number;
  createdAt: Date;
  metadata?: SecretMetadata;
  rotation?: RotationConfig;
  history?: SecretVersion[];
}

export interface SecretStore {
  get(key: string): Promise<StoredSecret | null>;
  set(key: string, secret: StoredSecret): Promise<void>;
  delete(key: string): Promise<void>;
  list(): Promise<string[]>;
}

export interface EncryptionProvider {
  encrypt(data: string): Promise<string>;
  decrypt(encrypted: string): Promise<string>;
}

export interface SecretAccessLog {
  secretName: string;
  action: 'read' | 'write' | 'delete' | 'rotate';
  accessor?: string;
  reason?: string;
  ip?: string;
  timestamp: Date;
  version?: number;
}

export interface RotationEvent {
  secretName: string;
  oldVersion: number;
  newVersion: number;
  timestamp: Date;
}

export interface SecretsConfig {
  store: SecretStore;
  encryption: EncryptionProvider;
  enableAudit?: boolean;
  maxAuditLogs?: number;
  cacheEnabled?: boolean;
  cacheTtl?: number;
  maxVersions?: number;
}

export interface GetSecretOptions {
  version?: number;
  accessor?: string;
  reason?: string;
  ip?: string;
}

export interface SetSecretOptions {
  accessor?: string;
  reason?: string;
  metadata?: SecretMetadata;
  rotation?: {
    policy: RotationPolicy;
    intervalDays?: number;
  };
}

export interface DeleteSecretOptions {
  accessor?: string;
  reason?: string;
}

type RotationHandler = (event: RotationEvent) => void;

/**
 * Secrets Manager implementation
 */
export class SecretsManager {
  private config: Required<Omit<SecretsConfig, 'store' | 'encryption'>> & {
    store: SecretStore;
    encryption: EncryptionProvider;
  };
  private accessLogs: Map<string, SecretAccessLog[]> = new Map();
  private cache: Map<string, { value: string; timestamp: number }> = new Map();
  private rotationHandlers: RotationHandler[] = [];

  constructor(config: SecretsConfig) {
    this.config = {
      store: config.store,
      encryption: config.encryption,
      enableAudit: config.enableAudit ?? false,
      maxAuditLogs: config.maxAuditLogs ?? 1000,
      cacheEnabled: config.cacheEnabled ?? false,
      cacheTtl: config.cacheTtl ?? 300000,
      maxVersions: config.maxVersions ?? 10,
    };
  }

  getConfig(): Partial<SecretsConfig> {
    return {
      enableAudit: this.config.enableAudit,
      cacheEnabled: this.config.cacheEnabled,
      cacheTtl: this.config.cacheTtl,
      maxVersions: this.config.maxVersions,
    };
  }

  async setSecret(name: string, value: string, options: SetSecretOptions = {}): Promise<void> {
    try {
      // Encrypt the value
      let encryptedValue: string;
      try {
        encryptedValue = await this.config.encryption.encrypt(value);
      } catch (error) {
        throw new Error('Failed to encrypt secret');
      }

      // Get existing secret for versioning
      const existing = await this.config.store.get(name);
      const newVersion = existing ? existing.version + 1 : 1;

      // Build history
      const history: SecretVersion[] = existing?.history || [];
      if (existing) {
        history.push({
          version: existing.version,
          value: existing.value,
          createdAt: existing.createdAt,
        });

        // Trim history to max versions
        while (history.length >= this.config.maxVersions) {
          history.shift();
        }
      }

      // Build rotation config
      let rotation: RotationConfig | undefined;
      if (options.rotation) {
        const now = new Date();
        rotation = {
          policy: options.rotation.policy,
          intervalDays: options.rotation.intervalDays,
          lastRotation: now,
          nextRotation: options.rotation.intervalDays
            ? new Date(now.getTime() + options.rotation.intervalDays * 24 * 60 * 60 * 1000)
            : undefined,
        };
      } else if (existing?.rotation) {
        rotation = existing.rotation;
      }

      // Store the secret
      try {
        await this.config.store.set(name, {
          value: encryptedValue,
          version: newVersion,
          createdAt: new Date(),
          metadata: options.metadata || existing?.metadata,
          rotation,
          history,
        });
      } catch (error) {
        throw new Error('Failed to store secret');
      }

      // Invalidate cache
      this.cache.delete(name);

      // Log access
      this.logAccess(name, 'write', options.accessor, options.reason, undefined, newVersion);
    } catch (error) {
      if (error instanceof Error && (
        error.message === 'Failed to encrypt secret' ||
        error.message === 'Failed to store secret'
      )) {
        throw error;
      }
      throw new Error('Failed to set secret');
    }
  }

  async getSecret(name: string, options: GetSecretOptions = {}): Promise<string | null> {
    // Check cache first
    if (this.config.cacheEnabled && !options.version) {
      const cached = this.cache.get(name);
      if (cached && Date.now() - cached.timestamp < this.config.cacheTtl) {
        this.logAccess(name, 'read', options.accessor, options.reason, options.ip);
        return cached.value;
      }
    }

    const stored = await this.config.store.get(name);
    if (!stored) {
      return null;
    }

    // Get specific version if requested
    let encryptedValue = stored.value;
    if (options.version && options.version !== stored.version) {
      const historicalVersion = stored.history?.find(v => v.version === options.version);
      if (historicalVersion?.value) {
        encryptedValue = historicalVersion.value;
      }
    }

    try {
      const decrypted = await this.config.encryption.decrypt(encryptedValue);

      // Update cache
      if (this.config.cacheEnabled && !options.version) {
        this.cache.set(name, { value: decrypted, timestamp: Date.now() });
      }

      // Log access
      this.logAccess(name, 'read', options.accessor, options.reason, options.ip, stored.version);

      return decrypted;
    } catch (error) {
      throw new Error('Failed to decrypt secret');
    }
  }

  async getSecrets(names: string[]): Promise<Record<string, string | null>> {
    const results: Record<string, string | null> = {};
    for (const name of names) {
      results[name] = await this.getSecret(name);
    }
    return results;
  }

  async setSecrets(secrets: Record<string, string>, options: SetSecretOptions = {}): Promise<void> {
    for (const [name, value] of Object.entries(secrets)) {
      await this.setSecret(name, value, options);
    }
  }

  async deleteSecret(name: string, options: DeleteSecretOptions = {}): Promise<void> {
    await this.config.store.delete(name);
    this.cache.delete(name);

    // Log access
    this.logAccess(name, 'delete', options.accessor, options.reason);
  }

  async listSecrets(filter?: { namespace?: string }): Promise<string[]> {
    const all = await this.config.store.list();

    if (filter?.namespace) {
      return all.filter(name => name.startsWith(`${filter.namespace}/`));
    }

    return all;
  }

  async getSecretMetadata(name: string): Promise<SecretMetadata | null> {
    const stored = await this.config.store.get(name);
    return stored?.metadata || null;
  }

  async getSecretVersions(name: string): Promise<SecretVersion[]> {
    const stored = await this.config.store.get(name);
    if (!stored) {
      return [];
    }

    const versions: SecretVersion[] = stored.history || [];
    versions.push({
      version: stored.version,
      createdAt: stored.createdAt,
    });

    return versions;
  }

  async needsRotation(name: string): Promise<boolean> {
    const stored = await this.config.store.get(name);
    if (!stored?.rotation || stored.rotation.policy === RotationPolicy.NONE) {
      return false;
    }

    if (!stored.rotation.nextRotation) {
      return false;
    }

    return Date.now() >= stored.rotation.nextRotation.getTime();
  }

  async rotateSecret(name: string, generator: () => Promise<string>): Promise<void> {
    const stored = await this.config.store.get(name);
    const oldVersion = stored?.version || 0;

    // Generate new secret value
    const newValue = await generator();

    // Set the new secret (this increments version)
    await this.setSecret(name, newValue);

    // Update rotation timestamps
    const updated = await this.config.store.get(name);
    if (updated && updated.rotation) {
      const now = new Date();
      updated.rotation.lastRotation = now;
      if (updated.rotation.intervalDays) {
        updated.rotation.nextRotation = new Date(
          now.getTime() + updated.rotation.intervalDays * 24 * 60 * 60 * 1000
        );
      }
      await this.config.store.set(name, updated);
    }

    // Log and notify
    this.logAccess(name, 'rotate');

    const event: RotationEvent = {
      secretName: name,
      oldVersion,
      newVersion: oldVersion + 1,
      timestamp: new Date(),
    };

    for (const handler of this.rotationHandlers) {
      try {
        handler(event);
      } catch {
        // Ignore handler errors
      }
    }
  }

  async getSecretsNeedingRotation(): Promise<string[]> {
    const all = await this.listSecrets();
    const needsRotation: string[] = [];

    for (const name of all) {
      if (await this.needsRotation(name)) {
        needsRotation.push(name);
      }
    }

    return needsRotation;
  }

  onRotation(handler: RotationHandler): void {
    this.rotationHandlers.push(handler);
  }

  getAccessLogs(secretName?: string): SecretAccessLog[] {
    if (secretName) {
      return this.accessLogs.get(secretName) || [];
    }

    const all: SecretAccessLog[] = [];
    for (const logs of this.accessLogs.values()) {
      all.push(...logs);
    }
    return all.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  invalidateCache(name?: string): void {
    if (name) {
      this.cache.delete(name);
    } else {
      this.cache.clear();
    }
  }

  private logAccess(
    secretName: string,
    action: SecretAccessLog['action'],
    accessor?: string,
    reason?: string,
    ip?: string,
    version?: number
  ): void {
    if (!this.config.enableAudit) {
      return;
    }

    const logs = this.accessLogs.get(secretName) || [];
    logs.push({
      secretName,
      action,
      accessor,
      reason,
      ip,
      version,
      timestamp: new Date(),
    });

    // Trim logs to max
    while (logs.length > this.config.maxAuditLogs) {
      logs.shift();
    }

    this.accessLogs.set(secretName, logs);
  }
}
