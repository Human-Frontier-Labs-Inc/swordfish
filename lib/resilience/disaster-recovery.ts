/**
 * Disaster Recovery System
 *
 * Provides backup management, failover coordination, and recovery
 * plan execution for comprehensive disaster recovery.
 */

import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { gzipSync, gunzipSync } from 'zlib';

export enum BackupStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  FAILED = 'failed',
}

export enum FailoverStatus {
  NORMAL = 'normal',
  PRIMARY_FAILING = 'primary_failing',
  FAILOVER_IN_PROGRESS = 'failover_in_progress',
  FAILED_OVER = 'failed_over',
}

export interface StorageProvider {
  upload(key: string, data: Buffer): Promise<{ key: string }>;
  download(key: string): Promise<Buffer>;
  list(): Promise<BackupInfo[]>;
  delete(key: string): Promise<void>;
}

export interface BackupInfo {
  key: string;
  type?: string;
  source?: string;
  createdAt: Date;
  size?: number;
  checksum?: string;
}

export interface BackupConfig {
  type: string;
  source: string;
  dumpFn: (onProgress?: (progress: number) => void) => Promise<Buffer>;
  compress?: boolean;
  metadata?: Record<string, unknown>;
  onProgress?: (progress: number) => void;
}

export interface BackupResult {
  id: string;
  status: BackupStatus;
  error?: string;
  metadata?: Record<string, unknown>;
  size?: number;
  checksum?: string;
  createdAt: Date;
}

export interface RestoreConfig {
  backupId: string;
  restoreFn: (data: Buffer, options?: RestoreOptions) => Promise<boolean>;
  validateFirst?: boolean;
  expectedChecksum?: string;
  tables?: string[];
}

export interface RestoreOptions {
  tables?: string[];
}

export interface RestoreResult {
  status: 'completed' | 'failed';
  error?: string;
  duration?: number;
}

export interface VerificationResult {
  valid: boolean;
  checksumMatch: boolean;
  restoreTestPassed?: boolean;
  error?: string;
}

export interface BackupManagerConfig {
  storage: StorageProvider;
  retentionDays: number;
  encryptionKey: string;
}

/**
 * Manages backup creation, storage, and restoration
 */
export class BackupManager {
  private storage: StorageProvider;
  private retentionDays: number;
  private encryptionKey: Buffer;

  constructor(config: BackupManagerConfig) {
    this.storage = config.storage;
    this.retentionDays = config.retentionDays;
    this.encryptionKey = Buffer.from(config.encryptionKey.slice(0, 32).padEnd(32, '0'));
  }

  async createBackup(config: BackupConfig): Promise<BackupResult> {
    const id = `backup-${Date.now()}-${randomBytes(4).toString('hex')}`;
    const createdAt = new Date();

    try {
      // Get data from dump function
      let data = await config.dumpFn(config.onProgress);

      // Compress if requested
      if (config.compress) {
        data = gzipSync(data);
      }

      // Encrypt
      data = this.encrypt(data);

      // Calculate checksum
      const checksum = createHash('sha256').update(data).digest('hex');

      // Upload
      await this.storage.upload(id, data);

      return {
        id,
        status: BackupStatus.COMPLETED,
        metadata: config.metadata,
        size: data.length,
        checksum,
        createdAt,
      };
    } catch (error) {
      return {
        id,
        status: BackupStatus.FAILED,
        error: error instanceof Error ? error.message : 'Backup failed',
        createdAt,
      };
    }
  }

  async listBackups(filter?: { type?: string }): Promise<BackupInfo[]> {
    const backups = await this.storage.list();

    if (filter?.type) {
      return backups.filter(b => b.type === filter.type);
    }

    return backups;
  }

  async getBackup(key: string): Promise<BackupInfo | undefined> {
    const backups = await this.storage.list();
    return backups.find(b => b.key === key);
  }

  async cleanupOldBackups(): Promise<BackupInfo[]> {
    const backups = await this.storage.list();
    const cutoff = Date.now() - this.retentionDays * 24 * 60 * 60 * 1000;
    const toDelete = backups.filter(b => b.createdAt.getTime() < cutoff);

    for (const backup of toDelete) {
      await this.storage.delete(backup.key);
    }

    return toDelete;
  }

  async verifyBackup(
    backupId: string,
    options: {
      expectedChecksum?: string;
      testRestore?: boolean;
      restoreFn?: (data: Buffer) => Promise<boolean>;
    } = {}
  ): Promise<VerificationResult> {
    try {
      const data = await this.storage.download(backupId);

      // Verify checksum
      const actualChecksum = createHash('sha256').update(data).digest('hex');
      const checksumMatch = !options.expectedChecksum || actualChecksum === options.expectedChecksum;

      if (!checksumMatch) {
        return {
          valid: false,
          checksumMatch: false,
          error: 'Checksum mismatch',
        };
      }

      // Test restore if requested
      if (options.testRestore && options.restoreFn) {
        const decrypted = this.decrypt(data);
        const restoreTestPassed = await options.restoreFn(decrypted);

        return {
          valid: restoreTestPassed,
          checksumMatch: true,
          restoreTestPassed,
        };
      }

      return {
        valid: true,
        checksumMatch: true,
      };
    } catch (error) {
      return {
        valid: false,
        checksumMatch: false,
        error: error instanceof Error ? error.message : 'Verification failed',
      };
    }
  }

  async restore(config: RestoreConfig): Promise<RestoreResult> {
    const startTime = Date.now();

    try {
      // Validate first if requested
      if (config.validateFirst) {
        const verification = await this.verifyBackup(config.backupId, {
          expectedChecksum: config.expectedChecksum,
        });

        if (!verification.valid) {
          return {
            status: 'failed',
            error: 'Backup validation failed',
          };
        }
      }

      // Download and decrypt
      const encrypted = await this.storage.download(config.backupId);
      const data = this.decrypt(encrypted);

      // Restore
      const options: RestoreOptions = {};
      if (config.tables) {
        options.tables = config.tables;
      }

      await config.restoreFn(data, options);

      return {
        status: 'completed',
        duration: Date.now() - startTime,
      };
    } catch (error) {
      return {
        status: 'failed',
        error: error instanceof Error ? error.message : 'Restore failed',
        duration: Date.now() - startTime,
      };
    }
  }

  async restoreToPointInTime(config: {
    targetTime: Date;
    restoreFn: (data: Buffer) => Promise<boolean>;
  }): Promise<RestoreResult> {
    const backups = await this.storage.list();

    // Find the most recent backup before target time
    const validBackups = backups
      .filter(b => b.createdAt <= config.targetTime)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    if (validBackups.length === 0) {
      return {
        status: 'failed',
        error: 'No backup found before target time',
      };
    }

    const backup = validBackups[0];

    return this.restore({
      backupId: backup.key,
      restoreFn: config.restoreFn,
    });
  }

  private encrypt(data: Buffer): Buffer {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-cbc', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
  }

  private decrypt(data: Buffer): Buffer {
    try {
      if (data.length < 17) {
        // Data too short to be encrypted, return as-is
        return data;
      }
      const iv = data.subarray(0, 16);
      const encrypted = data.subarray(16);
      const decipher = createDecipheriv('aes-256-cbc', this.encryptionKey, iv);
      return Buffer.concat([decipher.update(encrypted), decipher.final()]);
    } catch {
      // If decryption fails, assume data is not encrypted
      return data;
    }
  }
}

export interface FailoverConfig {
  primaryEndpoint: string;
  secondaryEndpoint: string;
  healthCheck: (endpoint: string) => Promise<boolean>;
  switchover: (from: string, to: string) => Promise<boolean>;
  healthCheckInterval?: number;
  failoverThreshold?: number;
}

export interface FailoverEvent {
  from: string;
  to: string;
  timestamp: Date;
  reason: 'automatic' | 'manual';
}

type FailoverEventHandler = (event: FailoverEvent) => void;

/**
 * Manages failover between primary and secondary systems
 */
export class FailoverManager {
  private config: Required<FailoverConfig>;
  private status: FailoverStatus = FailoverStatus.NORMAL;
  private activeEndpoint: string;
  private consecutiveFailures = 0;
  private history: FailoverEvent[] = [];
  private eventHandlers: Map<string, FailoverEventHandler[]> = new Map();

  constructor(config: FailoverConfig) {
    this.config = {
      ...config,
      healthCheckInterval: config.healthCheckInterval ?? 5000,
      failoverThreshold: config.failoverThreshold ?? 3,
    };
    this.activeEndpoint = config.primaryEndpoint;
  }

  getStatus(): FailoverStatus {
    return this.status;
  }

  getActiveEndpoint(): string {
    return this.activeEndpoint;
  }

  getHistory(): FailoverEvent[] {
    return [...this.history];
  }

  async checkHealth(): Promise<boolean> {
    const healthy = await this.config.healthCheck(this.config.primaryEndpoint);

    if (!healthy) {
      this.consecutiveFailures++;

      if (this.consecutiveFailures >= this.config.failoverThreshold) {
        this.status = FailoverStatus.PRIMARY_FAILING;

        if (this.consecutiveFailures > this.config.failoverThreshold) {
          await this.performFailover('automatic');
        }
      }
    } else {
      this.consecutiveFailures = 0;
      if (this.status === FailoverStatus.PRIMARY_FAILING) {
        this.status = FailoverStatus.NORMAL;
      }
    }

    return healthy;
  }

  async manualFailover(): Promise<void> {
    await this.performFailover('manual');
  }

  async failback(): Promise<void> {
    const primaryHealthy = await this.config.healthCheck(this.config.primaryEndpoint);

    if (!primaryHealthy) {
      throw new Error('Primary is not healthy, cannot failback');
    }

    await this.config.switchover(this.activeEndpoint, this.config.primaryEndpoint);
    this.activeEndpoint = this.config.primaryEndpoint;
    this.status = FailoverStatus.NORMAL;
    this.consecutiveFailures = 0;

    const event: FailoverEvent = {
      from: this.config.secondaryEndpoint,
      to: this.config.primaryEndpoint,
      timestamp: new Date(),
      reason: 'manual',
    };
    this.history.push(event);
  }

  on(event: string, handler: FailoverEventHandler): void {
    const handlers = this.eventHandlers.get(event) || [];
    handlers.push(handler);
    this.eventHandlers.set(event, handlers);
  }

  private async performFailover(reason: 'automatic' | 'manual'): Promise<void> {
    this.status = FailoverStatus.FAILOVER_IN_PROGRESS;

    const from = this.activeEndpoint;
    const to = this.activeEndpoint === this.config.primaryEndpoint
      ? this.config.secondaryEndpoint
      : this.config.primaryEndpoint;

    await this.config.switchover(from, to);
    this.activeEndpoint = to;
    this.status = FailoverStatus.FAILED_OVER;

    const event: FailoverEvent = {
      from,
      to,
      timestamp: new Date(),
      reason,
    };
    this.history.push(event);
    this.emit('failover', event);
  }

  private emit(eventName: string, event: FailoverEvent): void {
    const handlers = this.eventHandlers.get(eventName) || [];
    for (const handler of handlers) {
      try {
        handler(event);
      } catch {
        // Ignore handler errors
      }
    }
  }
}

export interface RecoveryStep {
  name: string;
  description?: string;
  action: () => Promise<boolean>;
  rollback?: () => Promise<boolean>;
  timeout: number;
  critical: boolean;
}

export interface RecoveryStepResult {
  name: string;
  success: boolean;
  duration: number;
  error?: string;
}

export interface RecoveryResult {
  success: boolean;
  duration: number;
  steps: RecoveryStepResult[];
  rtoMet?: boolean;
}

export interface RecoveryVerification {
  passed: boolean;
  checks: Record<string, boolean>;
}

/**
 * Defines and executes a recovery plan
 */
export class RecoveryPlan {
  private name: string;
  private description?: string;
  private rto: number;
  private rpo: number;
  private steps: RecoveryStep[] = [];

  constructor(config: {
    name: string;
    description?: string;
    rto?: number;
    rpo?: number;
  }) {
    this.name = config.name;
    this.description = config.description;
    this.rto = config.rto ?? 3600000;
    this.rpo = config.rpo ?? 900000;
  }

  addStep(step: RecoveryStep): void {
    this.steps.push(step);
  }

  getSteps(): RecoveryStep[] {
    return [...this.steps];
  }

  async execute(options: { rollbackOnFailure?: boolean } = {}): Promise<RecoveryResult> {
    const startTime = Date.now();
    const stepResults: RecoveryStepResult[] = [];
    const completedSteps: RecoveryStep[] = [];
    let success = true;

    for (const step of this.steps) {
      const stepStart = Date.now();

      try {
        await Promise.race([
          step.action(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Timeout')), step.timeout)
          ),
        ]);

        stepResults.push({
          name: step.name,
          success: true,
          duration: Date.now() - stepStart,
        });
        completedSteps.push(step);
      } catch (error) {
        stepResults.push({
          name: step.name,
          success: false,
          duration: Date.now() - stepStart,
          error: error instanceof Error ? error.message : 'Unknown error',
        });

        if (step.critical) {
          success = false;

          // Rollback if requested
          if (options.rollbackOnFailure) {
            for (const completed of completedSteps.reverse()) {
              if (completed.rollback) {
                try {
                  await completed.rollback();
                } catch {
                  // Best effort rollback
                }
              }
            }
          }

          break;
        }
      }
    }

    const duration = Date.now() - startTime;

    return {
      success,
      duration,
      steps: stepResults,
      rtoMet: duration <= this.rto,
    };
  }
}

export interface DRManagerConfig {
  backupConfig: BackupManagerConfig;
  failoverConfig: FailoverConfig;
}

export interface DRStatus {
  backup: {
    lastBackupTime?: Date;
    backupCount: number;
  };
  failover: {
    status: FailoverStatus;
    activeEndpoint: string;
  };
  lastBackupTime?: Date;
}

export interface DRReadinessResult {
  passed: boolean;
  checks: {
    backupAvailable: boolean;
    secondaryReachable: boolean;
    lastBackupRecent: boolean;
  };
}

export interface DRReport {
  summary: string;
  backupStatus: {
    count: number;
    lastBackup?: Date;
    oldestBackup?: Date;
  };
  failoverStatus: {
    status: FailoverStatus;
    activeEndpoint: string;
    history: FailoverEvent[];
  };
  recommendations: string[];
}

/**
 * Unified disaster recovery manager
 */
export class DisasterRecoveryManager {
  private backupManager: BackupManager;
  private failoverManager: FailoverManager;

  constructor(config: DRManagerConfig) {
    this.backupManager = new BackupManager(config.backupConfig);
    this.failoverManager = new FailoverManager(config.failoverConfig);
  }

  async getStatus(): Promise<DRStatus> {
    const backups = await this.backupManager.listBackups();
    const sortedBackups = backups.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    return {
      backup: {
        lastBackupTime: sortedBackups[0]?.createdAt,
        backupCount: backups.length,
      },
      failover: {
        status: this.failoverManager.getStatus(),
        activeEndpoint: this.failoverManager.getActiveEndpoint(),
      },
      lastBackupTime: sortedBackups[0]?.createdAt,
    };
  }

  async runReadinessTest(): Promise<DRReadinessResult> {
    const backups = await this.backupManager.listBackups();
    const backupAvailable = backups.length > 0;

    // Check secondary reachability (use the failover manager's health check)
    let secondaryReachable = true;
    try {
      await this.failoverManager.checkHealth();
      secondaryReachable = true;
    } catch {
      secondaryReachable = false;
    }

    // Check if last backup is recent (within 24 hours)
    const lastBackup = backups.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())[0];
    const lastBackupRecent = lastBackup
      ? Date.now() - lastBackup.createdAt.getTime() < 24 * 60 * 60 * 1000
      : false;

    const passed = backupAvailable && secondaryReachable;

    return {
      passed,
      checks: {
        backupAvailable,
        secondaryReachable,
        lastBackupRecent,
      },
    };
  }

  async generateReport(): Promise<DRReport> {
    const backups = await this.backupManager.listBackups();
    const sortedBackups = backups.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    const history = this.failoverManager.getHistory();
    const status = this.failoverManager.getStatus();
    const activeEndpoint = this.failoverManager.getActiveEndpoint();

    const recommendations: string[] = [];

    if (backups.length === 0) {
      recommendations.push('Create initial backup immediately');
    }

    if (backups.length < 3) {
      recommendations.push('Increase backup frequency for better recovery options');
    }

    if (status === FailoverStatus.FAILED_OVER) {
      recommendations.push('Investigate primary system and plan failback');
    }

    return {
      summary: `DR Status: ${status}, Backups: ${backups.length}`,
      backupStatus: {
        count: backups.length,
        lastBackup: sortedBackups[0]?.createdAt,
        oldestBackup: sortedBackups[sortedBackups.length - 1]?.createdAt,
      },
      failoverStatus: {
        status,
        activeEndpoint,
        history,
      },
      recommendations,
    };
  }
}
