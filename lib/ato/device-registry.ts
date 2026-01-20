/**
 * Device Registry - Device Detection and Management for ATO Prevention
 *
 * Provides device fingerprinting, known device registry, trust scoring,
 * and device approval workflows for account takeover detection.
 */

import { nanoid } from 'nanoid';
import { calculateDeviceTrustScore, type TrustFactors } from './device-trust';

// ============================================================================
// Types
// ============================================================================

export interface DeviceFingerprint {
  userAgent: string;
  screenResolution: string;
  timezone: string;
  language: string;
  platform: string;
  plugins?: string[];
  canvasHash?: string;
  webglHash?: string;
  audioHash?: string;
  fonts?: string[];
}

export interface DeviceMetadata {
  name: string;
  os: string;
  browser: string;
  ipAddress?: string;
  location?: {
    country?: string;
    city?: string;
    lat?: number;
    lng?: number;
  };
}

export type DeviceStatus = 'pending' | 'approved' | 'denied' | 'revoked' | 'expired';

export interface Device {
  id: string;
  userId: string;
  tenantId: string;
  fingerprint: string;
  fingerprintDetails?: DeviceFingerprint;
  metadata: DeviceMetadata;
  firstSeen: Date;
  lastSeen: Date;
  loginCount: number;
  status: DeviceStatus;
  trustScore: number;
  approvedBy?: string;
  approvedAt?: Date;
  deniedBy?: string;
  deniedAt?: Date;
  deniedReason?: string;
  revokedBy?: string;
  revokedAt?: Date;
  revokedReason?: string;
  expiredAt?: Date;
}

export interface DeviceTrust {
  deviceId: string | null;
  isTrusted: boolean;
  score: number;
  status: DeviceStatus | 'unknown';
  factors?: TrustFactors;
}

export interface Alert {
  id: string;
  type: 'new_device' | 'suspicious_device' | 'device_expired' | 'device_revoked';
  severity: 'low' | 'medium' | 'high' | 'critical';
  userId: string;
  deviceId: string;
  tenantId?: string;
  message: string;
  details: {
    deviceName?: string;
    os?: string;
    browser?: string;
    ipAddress?: string;
    fingerprint?: string;
  };
  context?: {
    vpnDetected?: boolean;
    impossibleTravel?: boolean;
    unusualTime?: boolean;
    newLocation?: boolean;
  };
  createdAt: Date;
}

export interface DeviceApprovalRequest {
  id: string;
  deviceId: string;
  userId: string;
  tenantId: string;
  status: 'pending' | 'approved' | 'rejected';
  requestedAt: Date;
  resolvedAt?: Date;
  resolvedBy?: string;
  rejectionReason?: string;
}

interface AlertContext {
  vpnDetected?: boolean;
  impossibleTravel?: boolean;
  unusualTime?: boolean;
  newLocation?: boolean;
}

// ============================================================================
// Fingerprint Comparison
// ============================================================================

/**
 * Compare two device fingerprints and return a similarity score (0-1)
 */
export function compareFingerprints(
  fp1: DeviceFingerprint,
  fp2: DeviceFingerprint
): number {
  const weights = {
    userAgent: 0.15,
    screenResolution: 0.10,
    timezone: 0.10,
    language: 0.05,
    platform: 0.10,
    plugins: 0.10,
    canvasHash: 0.20,
    webglHash: 0.20,
  };

  let totalWeight = 0;
  let totalScore = 0;

  // Core fields comparison
  type CoreField = 'userAgent' | 'screenResolution' | 'timezone' | 'language' | 'platform';
  const coreFields: CoreField[] = [
    'userAgent',
    'screenResolution',
    'timezone',
    'language',
    'platform',
  ];

  for (const field of coreFields) {
    const weight = weights[field];
    totalWeight += weight;

    if (fp1[field] === fp2[field]) {
      totalScore += weight;
    } else if (field === 'userAgent') {
      // Partial match for user agent (browser version updates)
      const similarity = calculateStringSimilarity(
        fp1.userAgent,
        fp2.userAgent
      );
      totalScore += weight * similarity;
    }
  }

  // Canvas hash comparison (higher weight)
  if (fp1.canvasHash !== undefined || fp2.canvasHash !== undefined) {
    totalWeight += weights.canvasHash;
    if (fp1.canvasHash === fp2.canvasHash) {
      totalScore += weights.canvasHash;
    }
  }

  // WebGL hash comparison (higher weight)
  if (fp1.webglHash !== undefined || fp2.webglHash !== undefined) {
    totalWeight += weights.webglHash;
    if (fp1.webglHash === fp2.webglHash) {
      totalScore += weights.webglHash;
    }
  }

  // Plugins comparison
  if (fp1.plugins && fp2.plugins) {
    totalWeight += weights.plugins;
    const pluginSimilarity = calculateArraySimilarity(fp1.plugins, fp2.plugins);
    totalScore += weights.plugins * pluginSimilarity;
  }

  return totalWeight > 0 ? totalScore / totalWeight : 0;
}

function calculateStringSimilarity(str1: string, str2: string): number {
  if (str1 === str2) return 1;
  if (!str1 || !str2) return 0;

  const len1 = str1.length;
  const len2 = str2.length;
  const maxLen = Math.max(len1, len2);

  if (maxLen === 0) return 1;

  // Simple character-level similarity
  let matches = 0;
  const minLen = Math.min(len1, len2);

  for (let i = 0; i < minLen; i++) {
    if (str1[i] === str2[i]) {
      matches++;
    }
  }

  return matches / maxLen;
}

function calculateArraySimilarity(arr1: string[], arr2: string[]): number {
  if (arr1.length === 0 && arr2.length === 0) return 1;
  if (arr1.length === 0 || arr2.length === 0) return 0;

  const set1 = new Set(arr1);
  const set2 = new Set(arr2);

  let intersection = 0;
  for (const item of set1) {
    if (set2.has(item)) {
      intersection++;
    }
  }

  const union = new Set([...arr1, ...arr2]).size;
  return intersection / union;
}

// ============================================================================
// Alert Generation
// ============================================================================

/**
 * Generate an alert for a new device
 */
export function generateDeviceAlert(
  userId: string,
  fingerprint: DeviceFingerprint,
  existingDevice: Device | null,
  context?: AlertContext
): Alert {
  const isKnownTrusted = existingDevice?.status === 'approved';

  let severity: Alert['severity'] = 'medium';
  let type: Alert['type'] = 'new_device';

  if (isKnownTrusted) {
    severity = 'info' as Alert['severity']; // Safe return
    return {
      id: `alert_${nanoid()}`,
      type: 'new_device',
      severity: 'low',
      userId,
      deviceId: existingDevice?.id || '',
      message: 'Login from known device',
      details: {
        deviceName: existingDevice?.metadata.name,
        os: existingDevice?.metadata.os,
        browser: existingDevice?.metadata.browser,
      },
      createdAt: new Date(),
    };
  }

  if (context?.vpnDetected || context?.impossibleTravel) {
    severity = 'high';
  }

  return {
    id: `alert_${nanoid()}`,
    type,
    severity,
    userId,
    deviceId: existingDevice?.id || '',
    message: `New device detected for user ${userId}`,
    details: {
      os: fingerprint.platform,
      browser: fingerprint.userAgent,
    },
    context,
    createdAt: new Date(),
  };
}

// ============================================================================
// Device Registry Class
// ============================================================================

export class DeviceRegistry {
  private devices: Map<string, Device> = new Map();
  private devicesByUser: Map<string, Set<string>> = new Map();
  private devicesByTenant: Map<string, Set<string>> = new Map();
  private approvalRequests: Map<string, DeviceApprovalRequest> = new Map();

  /**
   * Register a new device for a user
   */
  async registerDevice(
    userId: string,
    fingerprint: string,
    metadata: DeviceMetadata,
    tenantId: string = 'default'
  ): Promise<Device> {
    const id = `dev_${nanoid()}`;
    const now = new Date();

    const device: Device = {
      id,
      userId,
      tenantId,
      fingerprint,
      metadata,
      firstSeen: now,
      lastSeen: now,
      loginCount: 1,
      status: 'pending',
      trustScore: 0,
    };

    this.devices.set(id, device);

    // Index by user
    if (!this.devicesByUser.has(userId)) {
      this.devicesByUser.set(userId, new Set());
    }
    this.devicesByUser.get(userId)!.add(id);

    // Index by tenant
    if (!this.devicesByTenant.has(tenantId)) {
      this.devicesByTenant.set(tenantId, new Set());
    }
    this.devicesByTenant.get(tenantId)!.add(id);

    return device;
  }

  /**
   * Check if a device is known for a user
   */
  async isKnownDevice(userId: string, fingerprint: string): Promise<boolean> {
    const userDeviceIds = this.devicesByUser.get(userId);
    if (!userDeviceIds) return false;

    for (const deviceId of userDeviceIds) {
      const device = this.devices.get(deviceId);
      if (device && device.fingerprint === fingerprint) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get all devices for a user
   */
  async getDevicesForUser(userId: string, tenantId?: string): Promise<Device[]> {
    const userDeviceIds = this.devicesByUser.get(userId);
    if (!userDeviceIds) return [];

    const devices: Device[] = [];
    for (const deviceId of userDeviceIds) {
      const device = this.devices.get(deviceId);
      if (device) {
        if (tenantId && device.tenantId !== tenantId) {
          continue;
        }
        devices.push(device);
      }
    }

    return devices;
  }

  /**
   * Get all devices for a tenant
   */
  async getDevicesForTenant(tenantId: string): Promise<Device[]> {
    const tenantDeviceIds = this.devicesByTenant.get(tenantId);
    if (!tenantDeviceIds) return [];

    const devices: Device[] = [];
    for (const deviceId of tenantDeviceIds) {
      const device = this.devices.get(deviceId);
      if (device) {
        devices.push(device);
      }
    }

    return devices;
  }

  /**
   * Get a single device by ID
   */
  async getDevice(deviceId: string): Promise<Device | null> {
    return this.devices.get(deviceId) || null;
  }

  /**
   * Find device by fingerprint for a user
   */
  async findDeviceByFingerprint(
    userId: string,
    fingerprint: string
  ): Promise<Device | null> {
    const userDeviceIds = this.devicesByUser.get(userId);
    if (!userDeviceIds) return null;

    for (const deviceId of userDeviceIds) {
      const device = this.devices.get(deviceId);
      if (device && device.fingerprint === fingerprint) {
        return device;
      }
    }

    return null;
  }

  /**
   * Update device activity (last seen, login count)
   */
  async updateDeviceActivity(
    deviceId: string,
    metadataUpdates?: Partial<DeviceMetadata>
  ): Promise<void> {
    const device = this.devices.get(deviceId);
    if (!device) return;

    device.lastSeen = new Date();
    device.loginCount++;

    if (metadataUpdates) {
      device.metadata = {
        ...device.metadata,
        ...metadataUpdates,
      };
    }

    // Recalculate trust score
    device.trustScore = this.calculateTrustScore(device);
  }

  /**
   * Set device last seen (for testing)
   */
  async setDeviceLastSeen(deviceId: string, date: Date): Promise<void> {
    const device = this.devices.get(deviceId);
    if (device) {
      device.lastSeen = date;
    }
  }

  /**
   * Approve a device
   */
  async approveDevice(deviceId: string, approvedBy?: string): Promise<void> {
    const device = this.devices.get(deviceId);
    if (!device) {
      throw new Error(`Device ${deviceId} not found`);
    }

    device.status = 'approved';
    device.approvedBy = approvedBy;
    device.approvedAt = new Date();
    device.trustScore = this.calculateTrustScore(device);
  }

  /**
   * Deny a device
   */
  async denyDevice(
    deviceId: string,
    deniedBy: string,
    reason: string
  ): Promise<void> {
    const device = this.devices.get(deviceId);
    if (!device) {
      throw new Error(`Device ${deviceId} not found`);
    }

    device.status = 'denied';
    device.deniedBy = deniedBy;
    device.deniedAt = new Date();
    device.deniedReason = reason;
    device.trustScore = 0;
  }

  /**
   * Revoke a device
   */
  async revokeDevice(
    deviceId: string,
    revokedBy: string,
    reason: string
  ): Promise<void> {
    const device = this.devices.get(deviceId);
    if (!device) {
      throw new Error(`Device ${deviceId} not found`);
    }

    device.status = 'revoked';
    device.revokedBy = revokedBy;
    device.revokedAt = new Date();
    device.revokedReason = reason;
    device.trustScore = 0;
  }

  /**
   * Get pending approval requests for a tenant
   */
  async getPendingApprovals(tenantId: string): Promise<Device[]> {
    const devices: Device[] = [];
    const tenantDeviceIds = this.devicesByTenant.get(tenantId);

    if (!tenantDeviceIds) return [];

    for (const deviceId of tenantDeviceIds) {
      const device = this.devices.get(deviceId);
      if (device && device.status === 'pending') {
        devices.push(device);
      }
    }

    return devices;
  }

  /**
   * Check device trust status
   */
  async checkDeviceTrust(
    userId: string,
    fingerprint: string
  ): Promise<DeviceTrust> {
    const device = await this.findDeviceByFingerprint(userId, fingerprint);

    if (!device) {
      return {
        deviceId: null,
        isTrusted: false,
        score: 0,
        status: 'unknown',
      };
    }

    const score = this.calculateTrustScore(device);
    const isTrusted = device.status === 'approved' && score >= 50;

    return {
      deviceId: device.id,
      isTrusted,
      score,
      status: device.status,
    };
  }

  /**
   * Cleanup expired devices
   */
  async cleanupExpiredDevices(
    maxAgeDays: number = 90,
    tenantId?: string
  ): Promise<number> {
    const now = new Date();
    const maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
    let expiredCount = 0;

    for (const [deviceId, device] of this.devices) {
      // Skip if tenant filter doesn't match
      if (tenantId && device.tenantId !== tenantId) {
        continue;
      }

      // Only expire approved devices (pending/denied/revoked don't expire this way)
      if (device.status !== 'approved') {
        continue;
      }

      const lastSeenAge = now.getTime() - device.lastSeen.getTime();
      if (lastSeenAge > maxAgeMs) {
        device.status = 'expired';
        device.expiredAt = now;
        device.trustScore = 0;
        expiredCount++;
      }
    }

    return expiredCount;
  }

  /**
   * Generate a new device alert
   */
  async generateNewDeviceAlert(
    userId: string,
    device: Device,
    context?: AlertContext
  ): Promise<Alert> {
    let severity: Alert['severity'] = 'medium';

    if (context?.vpnDetected || context?.impossibleTravel) {
      severity = 'high';
    }

    return {
      id: `alert_${nanoid()}`,
      type: 'new_device',
      severity,
      userId,
      deviceId: device.id,
      tenantId: device.tenantId,
      message: `New device detected: ${device.metadata.name}`,
      details: {
        deviceName: device.metadata.name,
        os: device.metadata.os,
        browser: device.metadata.browser,
        ipAddress: device.metadata.ipAddress,
        fingerprint: device.fingerprint,
      },
      context,
      createdAt: new Date(),
    };
  }

  /**
   * Calculate trust score for a device
   */
  private calculateTrustScore(device: Device): number {
    const now = new Date();
    const ageInDays = Math.floor(
      (now.getTime() - device.firstSeen.getTime()) / (24 * 60 * 60 * 1000)
    );
    const lastLoginDaysAgo = Math.floor(
      (now.getTime() - device.lastSeen.getTime()) / (24 * 60 * 60 * 1000)
    );

    const factors: TrustFactors = {
      ageInDays,
      loginCount: device.loginCount,
      lastLoginDaysAgo,
      isApproved: device.status === 'approved',
      consistentLocation: true, // Would be calculated from login history
      consistentUsagePattern: true, // Would be calculated from login patterns
    };

    return calculateDeviceTrustScore(factors);
  }
}

// Default export for convenience
export default DeviceRegistry;
