/**
 * Secrets Management Tests
 * TDD: RED phase - Write failing tests first
 *
 * Secure secrets management with encryption at rest, rotation support,
 * and audit logging for credential access.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  SecretsManager,
  SecretsConfig,
  SecretVersion,
  SecretMetadata,
  RotationPolicy,
  SecretAccessLog,
  EncryptionProvider,
  SecretStore,
} from '../../lib/security/secrets-manager';

describe('Secrets Management', () => {
  let secretsManager: SecretsManager;
  let mockStore: SecretStore;
  let mockEncryption: EncryptionProvider;

  beforeEach(() => {
    vi.useFakeTimers();

    mockStore = {
      get: vi.fn(),
      set: vi.fn().mockResolvedValue(undefined),
      delete: vi.fn().mockResolvedValue(undefined),
      list: vi.fn().mockResolvedValue([]),
    };

    mockEncryption = {
      encrypt: vi.fn().mockImplementation((data: string) =>
        Promise.resolve(Buffer.from(`encrypted:${data}`).toString('base64'))
      ),
      decrypt: vi.fn().mockImplementation((encrypted: string) => {
        const data = Buffer.from(encrypted, 'base64').toString();
        return Promise.resolve(data.replace('encrypted:', ''));
      }),
    };

    secretsManager = new SecretsManager({
      store: mockStore,
      encryption: mockEncryption,
      enableAudit: true,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('Configuration', () => {
    it('should accept secrets manager configuration', () => {
      const config: SecretsConfig = {
        store: mockStore,
        encryption: mockEncryption,
        enableAudit: true,
        cacheEnabled: true,
        cacheTtl: 300000,
      };

      const manager = new SecretsManager(config);
      expect(manager.getConfig()).toMatchObject({
        enableAudit: true,
        cacheEnabled: true,
      });
    });

    it('should use default values for optional parameters', () => {
      const manager = new SecretsManager({
        store: mockStore,
        encryption: mockEncryption,
      });
      const config = manager.getConfig();

      expect(config.enableAudit).toBe(false);
      expect(config.cacheEnabled).toBe(false);
    });
  });

  describe('Secret Storage', () => {
    it('should store a secret with encryption', async () => {
      await secretsManager.setSecret('api-key', 'super-secret-value');

      expect(mockEncryption.encrypt).toHaveBeenCalledWith('super-secret-value');
      expect(mockStore.set).toHaveBeenCalled();
    });

    it('should retrieve a decrypted secret', async () => {
      const encryptedValue = Buffer.from('encrypted:my-secret').toString('base64');
      mockStore.get.mockResolvedValue({
        value: encryptedValue,
        version: 1,
        createdAt: new Date(),
      });

      const value = await secretsManager.getSecret('api-key');

      expect(value).toBe('my-secret');
      expect(mockEncryption.decrypt).toHaveBeenCalledWith(encryptedValue);
    });

    it('should return null for non-existent secret', async () => {
      mockStore.get.mockResolvedValue(null);

      const value = await secretsManager.getSecret('non-existent');

      expect(value).toBeNull();
    });

    it('should delete a secret', async () => {
      await secretsManager.deleteSecret('api-key');

      expect(mockStore.delete).toHaveBeenCalledWith('api-key');
    });

    it('should list all secret names', async () => {
      mockStore.list.mockResolvedValue(['secret-1', 'secret-2', 'secret-3']);

      const secrets = await secretsManager.listSecrets();

      expect(secrets).toEqual(['secret-1', 'secret-2', 'secret-3']);
    });

    it('should store metadata with secrets', async () => {
      await secretsManager.setSecret('api-key', 'value', {
        metadata: {
          description: 'API key for external service',
          owner: 'platform-team',
          tags: ['production', 'critical'],
        },
      });

      expect(mockStore.set).toHaveBeenCalledWith(
        'api-key',
        expect.objectContaining({
          metadata: expect.objectContaining({
            description: 'API key for external service',
          }),
        })
      );
    });

    it('should retrieve secret metadata', async () => {
      mockStore.get.mockResolvedValue({
        value: 'encrypted',
        version: 1,
        createdAt: new Date(),
        metadata: {
          description: 'Test secret',
          owner: 'test-team',
        },
      });

      const metadata = await secretsManager.getSecretMetadata('api-key');

      expect(metadata?.description).toBe('Test secret');
      expect(metadata?.owner).toBe('test-team');
    });
  });

  describe('Versioning', () => {
    it('should increment version on update', async () => {
      mockStore.get.mockResolvedValue({
        value: 'old-encrypted',
        version: 1,
        createdAt: new Date(),
      });

      await secretsManager.setSecret('api-key', 'new-value');

      expect(mockStore.set).toHaveBeenCalledWith(
        'api-key',
        expect.objectContaining({
          version: 2,
        })
      );
    });

    it('should track version history', async () => {
      mockStore.get.mockResolvedValue({
        value: 'encrypted',
        version: 3,
        createdAt: new Date(),
        history: [
          { version: 1, createdAt: new Date(Date.now() - 2000) },
          { version: 2, createdAt: new Date(Date.now() - 1000) },
        ],
      });

      const versions = await secretsManager.getSecretVersions('api-key');

      expect(versions).toHaveLength(3);
    });

    it('should retrieve specific version', async () => {
      mockStore.get.mockResolvedValue({
        value: 'encrypted-v3',
        version: 3,
        createdAt: new Date(),
        history: [
          { version: 1, value: 'encrypted-v1', createdAt: new Date() },
          { version: 2, value: 'encrypted-v2', createdAt: new Date() },
        ],
      });

      const value = await secretsManager.getSecret('api-key', { version: 2 });

      expect(mockEncryption.decrypt).toHaveBeenCalledWith('encrypted-v2');
    });

    it('should limit version history', async () => {
      const manager = new SecretsManager({
        store: mockStore,
        encryption: mockEncryption,
        maxVersions: 3,
      });

      mockStore.get.mockResolvedValue({
        value: 'encrypted',
        version: 4,
        createdAt: new Date(),
        history: [
          { version: 1, value: 'v1', createdAt: new Date() },
          { version: 2, value: 'v2', createdAt: new Date() },
          { version: 3, value: 'v3', createdAt: new Date() },
        ],
      });

      await manager.setSecret('api-key', 'new-value');

      // Should only keep 3 versions (new one + 2 from history)
      expect(mockStore.set).toHaveBeenCalledWith(
        'api-key',
        expect.objectContaining({
          history: expect.any(Array),
        })
      );

      const setCall = mockStore.set.mock.calls[0];
      expect(setCall[1].history.length).toBeLessThanOrEqual(3);
    });
  });

  describe('Secret Rotation', () => {
    it('should support scheduled rotation', async () => {
      const now = Date.now();
      vi.setSystemTime(now);

      await secretsManager.setSecret('api-key', 'value', {
        rotation: {
          policy: RotationPolicy.SCHEDULED,
          intervalDays: 30,
        },
      });

      mockStore.get.mockResolvedValue({
        value: 'encrypted',
        version: 1,
        createdAt: new Date(now),
        rotation: {
          policy: RotationPolicy.SCHEDULED,
          intervalDays: 30,
          lastRotation: new Date(now),
          nextRotation: new Date(now + 30 * 24 * 60 * 60 * 1000),
        },
      });

      const needsRotation = await secretsManager.needsRotation('api-key');
      expect(needsRotation).toBe(false);

      // Advance time past rotation interval
      vi.setSystemTime(now + 31 * 24 * 60 * 60 * 1000);

      const needsRotationAfter = await secretsManager.needsRotation('api-key');
      expect(needsRotationAfter).toBe(true);
    });

    it('should execute rotation with generator function', async () => {
      const generator = vi.fn().mockResolvedValue('new-secret-value');

      mockStore.get.mockResolvedValue({
        value: 'old-encrypted',
        version: 1,
        createdAt: new Date(),
        rotation: {
          policy: RotationPolicy.SCHEDULED,
          intervalDays: 30,
        },
      });

      await secretsManager.rotateSecret('api-key', generator);

      expect(generator).toHaveBeenCalled();
      expect(mockStore.set).toHaveBeenCalled();
    });

    it('should notify on rotation', async () => {
      const notifyFn = vi.fn();
      secretsManager.onRotation(notifyFn);

      mockStore.get.mockResolvedValue({
        value: 'old-encrypted',
        version: 1,
        createdAt: new Date(),
      });

      await secretsManager.rotateSecret('api-key', async () => 'new-value');

      expect(notifyFn).toHaveBeenCalledWith({
        secretName: 'api-key',
        oldVersion: 1,
        newVersion: 2,
        timestamp: expect.any(Date),
      });
    });

    it('should list secrets needing rotation', async () => {
      const now = Date.now();
      vi.setSystemTime(now);

      mockStore.list.mockResolvedValue(['secret-1', 'secret-2', 'secret-3']);

      mockStore.get
        .mockResolvedValueOnce({
          value: 'encrypted',
          version: 1,
          rotation: {
            policy: RotationPolicy.SCHEDULED,
            nextRotation: new Date(now - 1000), // Past due
          },
        })
        .mockResolvedValueOnce({
          value: 'encrypted',
          version: 1,
          rotation: {
            policy: RotationPolicy.SCHEDULED,
            nextRotation: new Date(now + 1000), // Future
          },
        })
        .mockResolvedValueOnce({
          value: 'encrypted',
          version: 1,
          // No rotation policy
        });

      const needsRotation = await secretsManager.getSecretsNeedingRotation();

      expect(needsRotation).toEqual(['secret-1']);
    });
  });

  describe('Audit Logging', () => {
    beforeEach(() => {
      secretsManager = new SecretsManager({
        store: mockStore,
        encryption: mockEncryption,
        enableAudit: true,
      });
    });

    it('should log secret access', async () => {
      mockStore.get.mockResolvedValue({
        value: 'encrypted',
        version: 1,
        createdAt: new Date(),
      });

      await secretsManager.getSecret('api-key', {
        accessor: 'user-123',
        reason: 'API request',
      });

      const logs = secretsManager.getAccessLogs('api-key');

      expect(logs).toHaveLength(1);
      expect(logs[0].accessor).toBe('user-123');
      expect(logs[0].reason).toBe('API request');
      expect(logs[0].action).toBe('read');
    });

    it('should log secret modifications', async () => {
      await secretsManager.setSecret('api-key', 'value', {
        accessor: 'admin-user',
        reason: 'Initial setup',
      });

      const logs = secretsManager.getAccessLogs('api-key');

      expect(logs.some(l => l.action === 'write')).toBe(true);
    });

    it('should log secret deletion', async () => {
      await secretsManager.deleteSecret('api-key', {
        accessor: 'admin-user',
        reason: 'Key deprecated',
      });

      const logs = secretsManager.getAccessLogs('api-key');

      expect(logs.some(l => l.action === 'delete')).toBe(true);
    });

    it('should include timestamp and IP in logs', async () => {
      const now = Date.now();
      vi.setSystemTime(now);

      mockStore.get.mockResolvedValue({
        value: 'encrypted',
        version: 1,
        createdAt: new Date(),
      });

      await secretsManager.getSecret('api-key', {
        accessor: 'user-123',
        ip: '192.168.1.1',
      });

      const logs = secretsManager.getAccessLogs('api-key');

      expect(logs[0].timestamp.getTime()).toBe(now);
      expect(logs[0].ip).toBe('192.168.1.1');
    });

    it('should limit audit log retention', async () => {
      secretsManager = new SecretsManager({
        store: mockStore,
        encryption: mockEncryption,
        enableAudit: true,
        maxAuditLogs: 5,
      });

      mockStore.get.mockResolvedValue({
        value: 'encrypted',
        version: 1,
        createdAt: new Date(),
      });

      // Generate many access logs
      for (let i = 0; i < 10; i++) {
        await secretsManager.getSecret('api-key', { accessor: `user-${i}` });
      }

      const logs = secretsManager.getAccessLogs('api-key');

      expect(logs.length).toBeLessThanOrEqual(5);
    });
  });

  describe('Caching', () => {
    beforeEach(() => {
      secretsManager = new SecretsManager({
        store: mockStore,
        encryption: mockEncryption,
        cacheEnabled: true,
        cacheTtl: 60000, // 1 minute
      });
    });

    it('should cache decrypted secrets', async () => {
      mockStore.get.mockResolvedValue({
        value: Buffer.from('encrypted:secret').toString('base64'),
        version: 1,
        createdAt: new Date(),
      });

      await secretsManager.getSecret('api-key');
      await secretsManager.getSecret('api-key');
      await secretsManager.getSecret('api-key');

      expect(mockStore.get).toHaveBeenCalledTimes(1);
      expect(mockEncryption.decrypt).toHaveBeenCalledTimes(1);
    });

    it('should invalidate cache on update', async () => {
      mockStore.get.mockResolvedValue({
        value: Buffer.from('encrypted:secret').toString('base64'),
        version: 1,
        createdAt: new Date(),
      });

      await secretsManager.getSecret('api-key');
      mockStore.get.mockClear(); // Clear calls before setSecret
      await secretsManager.setSecret('api-key', 'new-value');
      await secretsManager.getSecret('api-key');

      // setSecret calls get once (for versioning), getSecret calls get once (cache invalidated)
      expect(mockStore.get).toHaveBeenCalledTimes(2);
    });

    it('should respect cache TTL', async () => {
      mockStore.get.mockResolvedValue({
        value: Buffer.from('encrypted:secret').toString('base64'),
        version: 1,
        createdAt: new Date(),
      });

      await secretsManager.getSecret('api-key');

      // Advance time past cache TTL
      vi.advanceTimersByTime(60001);

      await secretsManager.getSecret('api-key');

      expect(mockStore.get).toHaveBeenCalledTimes(2);
    });

    it('should support manual cache invalidation', async () => {
      mockStore.get.mockResolvedValue({
        value: Buffer.from('encrypted:secret').toString('base64'),
        version: 1,
        createdAt: new Date(),
      });

      await secretsManager.getSecret('api-key');
      secretsManager.invalidateCache('api-key');
      await secretsManager.getSecret('api-key');

      expect(mockStore.get).toHaveBeenCalledTimes(2);
    });
  });

  describe('Namespacing', () => {
    it('should support namespaced secrets', async () => {
      await secretsManager.setSecret('production/api-key', 'prod-secret');
      await secretsManager.setSecret('staging/api-key', 'staging-secret');

      expect(mockStore.set).toHaveBeenCalledWith(
        'production/api-key',
        expect.anything()
      );
      expect(mockStore.set).toHaveBeenCalledWith(
        'staging/api-key',
        expect.anything()
      );
    });

    it('should list secrets by namespace', async () => {
      mockStore.list.mockResolvedValue([
        'production/api-key',
        'production/db-password',
        'staging/api-key',
      ]);

      const prodSecrets = await secretsManager.listSecrets({ namespace: 'production' });

      expect(prodSecrets).toEqual(['production/api-key', 'production/db-password']);
    });
  });

  describe('Error Handling', () => {
    it('should handle encryption failures gracefully', async () => {
      mockEncryption.encrypt.mockRejectedValue(new Error('Encryption failed'));

      await expect(secretsManager.setSecret('api-key', 'value'))
        .rejects.toThrow('Failed to encrypt secret');
    });

    it('should handle decryption failures gracefully', async () => {
      mockStore.get.mockResolvedValue({
        value: 'corrupted-data',
        version: 1,
        createdAt: new Date(),
      });
      mockEncryption.decrypt.mockRejectedValue(new Error('Decryption failed'));

      await expect(secretsManager.getSecret('api-key'))
        .rejects.toThrow('Failed to decrypt secret');
    });

    it('should handle store failures', async () => {
      mockStore.set.mockRejectedValue(new Error('Store unavailable'));

      await expect(secretsManager.setSecret('api-key', 'value'))
        .rejects.toThrow('Failed to store secret');
    });
  });

  describe('Bulk Operations', () => {
    it('should support bulk secret retrieval', async () => {
      mockStore.get
        .mockResolvedValueOnce({ value: Buffer.from('encrypted:secret1').toString('base64'), version: 1, createdAt: new Date() })
        .mockResolvedValueOnce({ value: Buffer.from('encrypted:secret2').toString('base64'), version: 1, createdAt: new Date() });

      const secrets = await secretsManager.getSecrets(['key1', 'key2']);

      expect(secrets).toEqual({
        key1: 'secret1',
        key2: 'secret2',
      });
    });

    it('should support bulk secret setting', async () => {
      await secretsManager.setSecrets({
        key1: 'value1',
        key2: 'value2',
        key3: 'value3',
      });

      expect(mockStore.set).toHaveBeenCalledTimes(3);
    });
  });
});
