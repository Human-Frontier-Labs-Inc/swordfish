/**
 * OAuth Token Encryption Tests
 * TDD: Write tests first, then implement
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Module will be created after tests
const ENCRYPTION_MODULE_PATH = '@/lib/security/encryption';

describe('OAuth Token Encryption', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    // Set up test encryption key (32 bytes for AES-256)
    process.env = {
      ...originalEnv,
      ENCRYPTION_KEY: 'test-encryption-key-32-bytes-ok!', // Exactly 32 chars
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('encrypt/decrypt', () => {
    it('should encrypt token with AES-256-GCM', async () => {
      const { encrypt } = await import(ENCRYPTION_MODULE_PATH);

      const token = 'ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxx';
      const encrypted = encrypt(token);

      // Encrypted should not equal plaintext
      expect(encrypted).not.toBe(token);

      // Should be in format: iv:tag:ciphertext (all hex)
      expect(encrypted).toMatch(/^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$/);
    });

    it('should decrypt token correctly', async () => {
      const { encrypt, decrypt } = await import(ENCRYPTION_MODULE_PATH);

      const token = 'ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxx';
      const encrypted = encrypt(token);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(token);
    });

    it('should use unique IV for each encryption', async () => {
      const { encrypt } = await import(ENCRYPTION_MODULE_PATH);

      const token = 'same_token_value';
      const enc1 = encrypt(token);
      const enc2 = encrypt(token);

      // Different IVs mean different ciphertext even for same input
      expect(enc1).not.toBe(enc2);

      // But both should decrypt to same value
      const { decrypt } = await import(ENCRYPTION_MODULE_PATH);
      expect(decrypt(enc1)).toBe(token);
      expect(decrypt(enc2)).toBe(token);
    });

    it('should handle empty string', async () => {
      const { encrypt, decrypt } = await import(ENCRYPTION_MODULE_PATH);

      const encrypted = encrypt('');
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe('');
    });

    it('should handle long tokens', async () => {
      const { encrypt, decrypt } = await import(ENCRYPTION_MODULE_PATH);

      // OAuth tokens can be quite long
      const longToken = 'a'.repeat(2048);
      const encrypted = encrypt(longToken);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(longToken);
    });

    it('should handle special characters in token', async () => {
      const { encrypt, decrypt } = await import(ENCRYPTION_MODULE_PATH);

      const tokenWithSpecialChars = 'ya29.a0AfH6/+==?&!@#$%^*()\n\t';
      const encrypted = encrypt(tokenWithSpecialChars);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(tokenWithSpecialChars);
    });

    it('should fail decryption with corrupted ciphertext', async () => {
      const { encrypt, decrypt } = await import(ENCRYPTION_MODULE_PATH);

      const token = 'valid_token';
      const encrypted = encrypt(token);

      // Corrupt the ciphertext part
      const parts = encrypted.split(':');
      parts[2] = 'corrupted' + parts[2].substring(9);
      const corrupted = parts.join(':');

      expect(() => decrypt(corrupted)).toThrow();
    });

    it('should fail decryption with corrupted auth tag', async () => {
      const { encrypt, decrypt } = await import(ENCRYPTION_MODULE_PATH);

      const token = 'valid_token';
      const encrypted = encrypt(token);

      // Corrupt the auth tag
      const parts = encrypted.split(':');
      parts[1] = 'deadbeef'.repeat(4); // 32 hex chars
      const corrupted = parts.join(':');

      expect(() => decrypt(corrupted)).toThrow();
    });

    it('should fail decryption with wrong format', async () => {
      const { decrypt } = await import(ENCRYPTION_MODULE_PATH);

      expect(() => decrypt('not-valid-format')).toThrow();
      expect(() => decrypt('only:two:parts:extra')).toThrow();
      expect(() => decrypt('')).toThrow();
    });
  });

  describe('key management', () => {
    it('should throw if ENCRYPTION_KEY is not set', async () => {
      delete process.env.ENCRYPTION_KEY;

      // Re-import module to pick up new env
      vi.resetModules();
      const { getEncryptionKey } = await import(ENCRYPTION_MODULE_PATH);

      expect(() => getEncryptionKey()).toThrow('ENCRYPTION_KEY environment variable is required');
    });

    it('should throw if ENCRYPTION_KEY is wrong length', async () => {
      process.env.ENCRYPTION_KEY = 'too-short';

      vi.resetModules();
      const { getEncryptionKey } = await import(ENCRYPTION_MODULE_PATH);

      expect(() => getEncryptionKey()).toThrow('ENCRYPTION_KEY must be exactly 32 characters');
    });

    it('should derive consistent key from environment', async () => {
      const { getEncryptionKey } = await import(ENCRYPTION_MODULE_PATH);

      const key1 = getEncryptionKey();
      const key2 = getEncryptionKey();

      expect(key1).toEqual(key2);
    });
  });

  describe('encryptToken / decryptToken helpers', () => {
    it('should encrypt null/undefined gracefully', async () => {
      const { encryptToken } = await import(ENCRYPTION_MODULE_PATH);

      expect(encryptToken(null as unknown as string)).toBeNull();
      expect(encryptToken(undefined as unknown as string)).toBeNull();
    });

    it('should decrypt null/undefined gracefully', async () => {
      const { decryptToken } = await import(ENCRYPTION_MODULE_PATH);

      expect(decryptToken(null as unknown as string)).toBeNull();
      expect(decryptToken(undefined as unknown as string)).toBeNull();
    });

    it('should handle decrypt errors gracefully with logging', async () => {
      const { decryptToken } = await import(ENCRYPTION_MODULE_PATH);

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      // Invalid encrypted value should return null and log error
      const result = decryptToken('invalid-encrypted-value');

      expect(result).toBeNull();
      expect(consoleSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });

  describe('isEncrypted helper', () => {
    it('should detect encrypted values', async () => {
      const { encrypt, isEncrypted } = await import(ENCRYPTION_MODULE_PATH);

      const token = 'plaintext_token';
      const encrypted = encrypt(token);

      expect(isEncrypted(token)).toBe(false);
      expect(isEncrypted(encrypted)).toBe(true);
    });

    it('should return false for null/undefined', async () => {
      const { isEncrypted } = await import(ENCRYPTION_MODULE_PATH);

      expect(isEncrypted(null as unknown as string)).toBe(false);
      expect(isEncrypted(undefined as unknown as string)).toBe(false);
      expect(isEncrypted('')).toBe(false);
    });
  });

  describe('integration config encryption', () => {
    it('should encrypt OAuth tokens in integration config', async () => {
      const { encryptIntegrationConfig, decryptIntegrationConfig } = await import(ENCRYPTION_MODULE_PATH);

      const config = {
        accessToken: 'ya29.a0AfH6SMBxxxxxxx',
        refreshToken: '1//0gxxxxxxxxxxxxxxx',
        email: 'user@example.com',
        syncEnabled: true,
      };

      const encrypted = encryptIntegrationConfig(config);

      // Tokens should be encrypted
      expect(encrypted.accessToken).not.toBe(config.accessToken);
      expect(encrypted.refreshToken).not.toBe(config.refreshToken);

      // Non-sensitive fields should remain unchanged
      expect(encrypted.email).toBe(config.email);
      expect(encrypted.syncEnabled).toBe(config.syncEnabled);

      // Should decrypt back to original
      const decrypted = decryptIntegrationConfig(encrypted);
      expect(decrypted.accessToken).toBe(config.accessToken);
      expect(decrypted.refreshToken).toBe(config.refreshToken);
    });

    it('should handle config without tokens', async () => {
      const { encryptIntegrationConfig, decryptIntegrationConfig } = await import(ENCRYPTION_MODULE_PATH);

      const config = {
        email: 'user@example.com',
        syncEnabled: true,
      };

      const encrypted = encryptIntegrationConfig(config);
      const decrypted = decryptIntegrationConfig(encrypted);

      expect(decrypted).toEqual(config);
    });

    it('should handle already encrypted config (idempotent)', async () => {
      const { encryptIntegrationConfig, isEncrypted } = await import(ENCRYPTION_MODULE_PATH);

      const config = {
        accessToken: 'ya29.a0AfH6SMBxxxxxxx',
        refreshToken: '1//0gxxxxxxxxxxxxxxx',
      };

      const encrypted1 = encryptIntegrationConfig(config);
      const encrypted2 = encryptIntegrationConfig(encrypted1);

      // Should detect already encrypted and not double-encrypt
      expect(isEncrypted(encrypted1.accessToken as string)).toBe(true);
      expect(isEncrypted(encrypted2.accessToken as string)).toBe(true);

      // Encrypted values should be the same (already encrypted)
      expect(encrypted2.accessToken).toBe(encrypted1.accessToken);
    });
  });
});
