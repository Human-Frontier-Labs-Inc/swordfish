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
const KEY_BYTES = 32; // AES-256 requires a 256-bit (32-byte) key

// Version prefix for ciphertext produced by the current scheme.
// Legacy ciphertext has NO prefix and is `iv:authTag:ciphertext` (all hex).
// New ciphertext is `v1:iv:authTag:ciphertext` (all hex).
const CIPHERTEXT_VERSION = 'v1';

/**
 * Decode the ENCRYPTION_KEY env var into a raw 32-byte buffer.
 *
 * Accepts (in order of preference):
 *   1. 64-char hex string  -> 32 bytes
 *   2. base64 string that decodes cleanly to exactly 32 bytes
 *   3. raw utf8 string that is exactly 32 bytes long
 *
 * SECURITY: validates the DECODED key is exactly 32 bytes, not the character
 * count. A 32-character hex string is only 16 bytes and would silently produce
 * a weak key under the old (character-count) check.
 */
function decodeEncryptionKey(key: string): Buffer {
  // 1. Hex (most common for generated keys: `openssl rand -hex 32`)
  if (/^[0-9a-fA-F]{64}$/.test(key)) {
    return Buffer.from(key, 'hex');
  }

  // 2. Base64 that round-trips to exactly 32 bytes
  //    (guards against arbitrary strings that happen to base64-decode)
  const base64Decoded = Buffer.from(key, 'base64');
  if (base64Decoded.length === KEY_BYTES && base64Decoded.toString('base64').replace(/=+$/, '') === key.replace(/=+$/, '')) {
    return base64Decoded;
  }

  // 3. Raw utf8 key (legacy / dev keys), must be exactly 32 bytes
  return Buffer.from(key, 'utf8');
}

/**
 * Get the encryption key from environment
 * @throws Error if key is not set or does not decode to exactly 32 bytes
 */
export function getEncryptionKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY;

  if (!key) {
    throw new Error('ENCRYPTION_KEY environment variable is required');
  }

  const decoded = decodeEncryptionKey(key);

  if (decoded.length !== KEY_BYTES) {
    throw new Error(
      `ENCRYPTION_KEY must decode to exactly 32 bytes (got ${decoded.length}). ` +
        'Provide a 64-char hex string, a 32-byte base64 string, or a 32-character raw key.'
    );
  }

  return decoded;
}

/**
 * Encrypt a plaintext string using AES-256-GCM
 * @param plaintext The string to encrypt
 * @returns Versioned encrypted string in format: v1:iv:authTag:ciphertext (all hex)
 */
export function encrypt(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  // New ciphertext carries a version prefix so the scheme can evolve.
  return `${CIPHERTEXT_VERSION}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt an encrypted string.
 *
 * Supports two on-disk formats:
 *   - Versioned (current):  v1:iv:authTag:ciphertext  (4 parts)
 *   - Legacy (unprefixed):  iv:authTag:ciphertext     (3 parts)
 *
 * @param encryptedString The encrypted string
 * @returns Decrypted plaintext
 * @throws Error if decryption fails (wrong key, corrupted data, etc.)
 */
export function decrypt(encryptedString: string): string {
  if (!encryptedString || typeof encryptedString !== 'string') {
    throw new Error('Invalid encrypted string');
  }

  const parts = encryptedString.split(':');

  let ivHex: string;
  let authTagHex: string;
  let ciphertextHex: string;

  if (parts.length === 4 && parts[0] === CIPHERTEXT_VERSION) {
    // Versioned: v1:iv:authTag:ciphertext
    [, ivHex, authTagHex, ciphertextHex] = parts;
  } else if (parts.length === 3) {
    // Legacy unprefixed: iv:authTag:ciphertext
    [ivHex, authTagHex, ciphertextHex] = parts;
  } else {
    throw new Error('Invalid encrypted string format');
  }

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

  // Supported formats:
  //   - versioned: v1:iv:authTag:ciphertext (4 parts)
  //   - legacy:    iv:authTag:ciphertext     (3 parts)
  const rawParts = value.split(':');

  let parts: string[];
  if (rawParts.length === 4 && rawParts[0] === CIPHERTEXT_VERSION) {
    parts = rawParts.slice(1);
  } else if (rawParts.length === 3) {
    parts = rawParts;
  } else {
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
