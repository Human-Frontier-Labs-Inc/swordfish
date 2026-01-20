/**
 * Token Encryption Module
 *
 * Provides AES-256-GCM encryption for OAuth tokens at rest.
 * Uses Node.js crypto module for cryptographic operations.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits recommended for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits

/**
 * Get the encryption key from environment
 * @throws Error if key is not set or invalid length
 */
export function getEncryptionKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY;

  if (!key) {
    throw new Error('ENCRYPTION_KEY environment variable is required');
  }

  if (key.length !== 32) {
    throw new Error('ENCRYPTION_KEY must be exactly 32 characters');
  }

  return Buffer.from(key, 'utf8');
}

/**
 * Encrypt a plaintext string using AES-256-GCM
 * @param plaintext The string to encrypt
 * @returns Encrypted string in format: iv:authTag:ciphertext (all hex)
 */
export function encrypt(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt an encrypted string
 * @param encryptedString String in format: iv:authTag:ciphertext (all hex)
 * @returns Decrypted plaintext
 * @throws Error if decryption fails (wrong key, corrupted data, etc.)
 */
export function decrypt(encryptedString: string): string {
  if (!encryptedString || typeof encryptedString !== 'string') {
    throw new Error('Invalid encrypted string');
  }

  const parts = encryptedString.split(':');

  if (parts.length !== 3) {
    throw new Error('Invalid encrypted string format');
  }

  const [ivHex, authTagHex, ciphertextHex] = parts;

  const key = getEncryptionKey();
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertextHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Check if a string appears to be encrypted (in our format)
 */
export function isEncrypted(value: string): boolean {
  if (!value || typeof value !== 'string') {
    return false;
  }

  // Check for our format: iv:authTag:ciphertext (all hex)
  const parts = value.split(':');
  if (parts.length !== 3) {
    return false;
  }

  const [iv, authTag, ciphertext] = parts;

  // IV should be 24 hex chars (12 bytes)
  if (!/^[a-f0-9]{24}$/i.test(iv)) {
    return false;
  }

  // Auth tag should be 32 hex chars (16 bytes)
  if (!/^[a-f0-9]{32}$/i.test(authTag)) {
    return false;
  }

  // Ciphertext should be hex
  if (!/^[a-f0-9]+$/i.test(ciphertext)) {
    return false;
  }

  return true;
}

/**
 * Encrypt a token with null safety
 * @returns Encrypted token or null if input is null/undefined
 */
export function encryptToken(token: string | null | undefined): string | null {
  if (token === null || token === undefined) {
    return null;
  }

  return encrypt(token);
}

/**
 * Decrypt a token with null safety and error handling
 * @returns Decrypted token or null if input is null/undefined or decryption fails
 */
export function decryptToken(encryptedToken: string | null | undefined): string | null {
  if (encryptedToken === null || encryptedToken === undefined) {
    return null;
  }

  try {
    return decrypt(encryptedToken);
  } catch (error) {
    console.error('Failed to decrypt token:', error instanceof Error ? error.message : 'Unknown error');
    return null;
  }
}

/**
 * Fields in integration config that contain sensitive tokens
 */
const SENSITIVE_FIELDS = ['accessToken', 'refreshToken', 'access_token', 'refresh_token'];

/**
 * Encrypt sensitive fields in an integration config object
 * @param config Integration config with potential token fields
 * @returns Config with sensitive fields encrypted
 */
export function encryptIntegrationConfig<T extends Record<string, unknown>>(config: T): T {
  if (!config || typeof config !== 'object') {
    return config;
  }

  const result = { ...config };

  for (const field of SENSITIVE_FIELDS) {
    if (field in result && typeof result[field] === 'string') {
      const value = result[field] as string;

      // Don't double-encrypt
      if (!isEncrypted(value)) {
        (result as Record<string, unknown>)[field] = encrypt(value);
      }
    }
  }

  return result;
}

/**
 * Decrypt sensitive fields in an integration config object
 * @param config Integration config with encrypted token fields
 * @returns Config with sensitive fields decrypted
 */
export function decryptIntegrationConfig<T extends Record<string, unknown>>(config: T): T {
  if (!config || typeof config !== 'object') {
    return config;
  }

  const result = { ...config };

  for (const field of SENSITIVE_FIELDS) {
    if (field in result && typeof result[field] === 'string') {
      const value = result[field] as string;

      // Only decrypt if it looks encrypted
      if (isEncrypted(value)) {
        const decrypted = decryptToken(value);
        if (decrypted !== null) {
          (result as Record<string, unknown>)[field] = decrypted;
        }
      }
    }
  }

  return result;
}
