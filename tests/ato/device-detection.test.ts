/**
 * Device Detection Tests
 *
 * Tests for device fingerprinting, known device registry, trust scoring,
 * and device approval workflows.
 */

import {
  DeviceRegistry,
  compareFingerprints,
  generateDeviceAlert,
  type Device,
  type DeviceFingerprint,
  type DeviceMetadata,
  type DeviceTrust,
  type Alert,
  type DeviceApprovalRequest,
} from '@/lib/ato/device-registry';
import { calculateDeviceTrustScore, type TrustFactors } from '@/lib/ato/device-trust';

describe('Device Detection', () => {
  describe('Device Fingerprint Comparison - Exact Match', () => {
    it('should identify identical fingerprints with 1.0 similarity', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        screenResolution: '1920x1080',
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'MacIntel',
        plugins: ['PDF Viewer', 'Chrome PDF Viewer'],
        canvasHash: 'abc123def456',
        webglHash: 'xyz789ghi012',
      };

      const fp2 = { ...fp1 };

      const similarity = compareFingerprints(fp1, fp2);

      expect(similarity).toBe(1.0);
    });

    it('should return 1.0 for fingerprints with identical core fields', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Chrome/120',
        screenResolution: '2560x1440',
        timezone: 'UTC',
        language: 'en',
        platform: 'Win32',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'Chrome/120',
        screenResolution: '2560x1440',
        timezone: 'UTC',
        language: 'en',
        platform: 'Win32',
      };

      expect(compareFingerprints(fp1, fp2)).toBe(1.0);
    });
  });

  describe('Device Fingerprint Similarity Scoring', () => {
    it('should detect completely different fingerprints with low similarity', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        screenResolution: '1920x1080',
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'MacIntel',
        plugins: ['PDF Viewer'],
        canvasHash: 'abc123',
        webglHash: 'def456',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        screenResolution: '2560x1440',
        timezone: 'Europe/London',
        language: 'en-GB',
        platform: 'Win32',
        plugins: ['Flash Player'],
        canvasHash: 'xyz789',
        webglHash: 'ghi012',
      };

      const similarity = compareFingerprints(fp1, fp2);

      expect(similarity).toBeLessThan(0.3);
    });

    it('should calculate partial similarity for similar devices (browser update)', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        screenResolution: '1920x1080',
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'MacIntel',
        plugins: ['PDF Viewer'],
        canvasHash: 'abc123',
        webglHash: 'def456',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.37',
        screenResolution: '1920x1080',
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'MacIntel',
        plugins: ['PDF Viewer', 'New Plugin'],
        canvasHash: 'abc123',
        webglHash: 'def456',
      };

      const similarity = compareFingerprints(fp1, fp2);

      expect(similarity).toBeGreaterThan(0.7);
      expect(similarity).toBeLessThan(1.0);
    });

    it('should handle missing fingerprint fields gracefully', () => {
      const fp1: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0',
        screenResolution: '1920x1080',
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'MacIntel',
      };

      const fp2: DeviceFingerprint = {
        userAgent: 'Mozilla/5.0',
        screenResolution: '1920x1080',
        timezone: 'America/New_York',
        language: 'en-US',
        platform: 'MacIntel',
      };

      const similarity = compareFingerprints(fp1, fp2);

      expect(similarity).toBe(1.0);
    });

    it('should weight canvas and webgl hashes higher in similarity calculation', () => {
      const baseFingerprint: DeviceFingerprint = {
        userAgent: 'Chrome/120',
        screenResolution: '1920x1080',
        timezone: 'UTC',
        language: 'en',
        platform: 'MacIntel',
        canvasHash: 'unique123',
        webglHash: 'unique456',
      };

      const differentBrowser: DeviceFingerprint = {
        ...baseFingerprint,
        userAgent: 'Firefox/121',
      };

      const differentCanvas: DeviceFingerprint = {
        ...baseFingerprint,
        canvasHash: 'different123',
        webglHash: 'different456',
      };

      const browserSimilarity = compareFingerprints(baseFingerprint, differentBrowser);
      const canvasSimilarity = compareFingerprints(baseFingerprint, differentCanvas);

      // Canvas/WebGL differences should impact similarity more
      expect(browserSimilarity).toBeGreaterThan(canvasSimilarity);
    });
  });

  describe('Known Device Registry', () => {
    let registry: DeviceRegistry;
    const userId = 'user123';
    const tenantId = 'tenant1';

    beforeEach(() => {
      registry = new DeviceRegistry();
    });

    it('should register a new device for a user', async () => {
      const metadata: DeviceMetadata = {
        name: 'Work Laptop',
        os: 'macOS 14.0',
        browser: 'Chrome 120',
        ipAddress: '192.168.1.100',
      };

      const fingerprint = 'fp_abc123def456';

      const device = await registry.registerDevice(userId, fingerprint, metadata, tenantId);

      expect(device).toBeDefined();
      expect(device.userId).toBe(userId);
      expect(device.fingerprint).toBe(fingerprint);
      expect(device.metadata.name).toBe('Work Laptop');
      expect(device.status).toBe('pending');
    });

    it('should check if device is known for user', async () => {
      const fingerprint = 'fp_known123';
      const metadata: DeviceMetadata = {
        name: 'Known Device',
        os: 'Windows 11',
        browser: 'Edge',
      };

      await registry.registerDevice(userId, fingerprint, metadata, tenantId);

      const isKnown = await registry.isKnownDevice(userId, fingerprint);
      const isUnknown = await registry.isKnownDevice(userId, 'fp_unknown456');

      expect(isKnown).toBe(true);
      expect(isUnknown).toBe(false);
    });

    it('should retrieve all devices for a user', async () => {
      const metadata: DeviceMetadata = {
        name: 'Device',
        os: 'OS',
        browser: 'Browser',
      };

      await registry.registerDevice(userId, 'fp1', { ...metadata, name: 'Device 1' }, tenantId);
      await registry.registerDevice(userId, 'fp2', { ...metadata, name: 'Device 2' }, tenantId);
      await registry.registerDevice(userId, 'fp3', { ...metadata, name: 'Device 3' }, tenantId);

      const devices = await registry.getDevicesForUser(userId);

      expect(devices).toHaveLength(3);
      expect(devices.map(d => d.metadata.name)).toContain('Device 1');
      expect(devices.map(d => d.metadata.name)).toContain('Device 2');
      expect(devices.map(d => d.metadata.name)).toContain('Device 3');
    });

    it('should update device last seen on re-login', async () => {
      const fingerprint = 'fp_update123';
      const metadata: DeviceMetadata = { name: 'Test', os: 'OS', browser: 'Browser' };

      const device = await registry.registerDevice(userId, fingerprint, metadata, tenantId);
      const initialLastSeen = device.lastSeen;

      // Simulate time passing
      await new Promise(resolve => setTimeout(resolve, 10));

      await registry.updateDeviceActivity(device.id);
      const updated = await registry.getDevice(device.id);

      expect(updated?.lastSeen.getTime()).toBeGreaterThan(initialLastSeen.getTime());
      expect(updated?.loginCount).toBe(2);
    });

    it('should find device by fingerprint with similarity matching', async () => {
      const fingerprint = 'fp_exact_match';
      const metadata: DeviceMetadata = { name: 'Test', os: 'OS', browser: 'Browser' };

      await registry.registerDevice(userId, fingerprint, metadata, tenantId);

      const found = await registry.findDeviceByFingerprint(userId, fingerprint);
      const notFound = await registry.findDeviceByFingerprint(userId, 'fp_different');

      expect(found).toBeDefined();
      expect(found?.fingerprint).toBe(fingerprint);
      expect(notFound).toBeNull();
    });
  });

  describe('New Device Alert Generation', () => {
    let registry: DeviceRegistry;

    beforeEach(() => {
      registry = new DeviceRegistry();
    });

    it('should generate alert for completely new device', async () => {
      const device: Device = {
        id: 'dev_new123',
        userId: 'user123',
        tenantId: 'tenant1',
        fingerprint: 'fp_new_device',
        metadata: {
          name: 'Unknown Device',
          os: 'Unknown',
          browser: 'Unknown',
        },
        firstSeen: new Date(),
        lastSeen: new Date(),
        loginCount: 1,
        status: 'pending',
        trustScore: 0,
      };

      const alert = await registry.generateNewDeviceAlert('user123', device);

      expect(alert).toBeDefined();
      expect(alert.type).toBe('new_device');
      expect(alert.severity).toBe('medium');
      expect(alert.userId).toBe('user123');
      expect(alert.deviceId).toBe(device.id);
    });

    it('should generate high severity alert for device from suspicious context', async () => {
      const device: Device = {
        id: 'dev_suspicious',
        userId: 'user123',
        tenantId: 'tenant1',
        fingerprint: 'fp_suspicious',
        metadata: {
          name: 'Unknown',
          os: 'Unknown',
          browser: 'Unknown',
          ipAddress: '185.220.101.1', // Tor exit node
        },
        firstSeen: new Date(),
        lastSeen: new Date(),
        loginCount: 1,
        status: 'pending',
        trustScore: 0,
      };

      const alert = await registry.generateNewDeviceAlert('user123', device, {
        vpnDetected: true,
        impossibleTravel: true,
      });

      expect(alert.severity).toBe('high');
      expect(alert.context?.vpnDetected).toBe(true);
      expect(alert.context?.impossibleTravel).toBe(true);
    });

    it('should include device metadata in alert details', async () => {
      const device: Device = {
        id: 'dev_meta',
        userId: 'user123',
        tenantId: 'tenant1',
        fingerprint: 'fp_metadata',
        metadata: {
          name: 'iPhone 15 Pro',
          os: 'iOS 17.2',
          browser: 'Safari 17',
          ipAddress: '98.234.56.78',
        },
        firstSeen: new Date(),
        lastSeen: new Date(),
        loginCount: 1,
        status: 'pending',
        trustScore: 0,
      };

      const alert = await registry.generateNewDeviceAlert('user123', device);

      expect(alert.details.deviceName).toBe('iPhone 15 Pro');
      expect(alert.details.os).toBe('iOS 17.2');
      expect(alert.details.browser).toBe('Safari 17');
    });
  });

  describe('Device Trust Scoring', () => {
    it('should calculate high trust for old, frequently used approved device', () => {
      const factors: TrustFactors = {
        ageInDays: 180,
        loginCount: 200,
        lastLoginDaysAgo: 1,
        isApproved: true,
        consistentLocation: true,
        consistentUsagePattern: true,
      };

      const score = calculateDeviceTrustScore(factors);

      expect(score).toBeGreaterThan(80);
    });

    it('should calculate low trust for brand new device', () => {
      const factors: TrustFactors = {
        ageInDays: 0,
        loginCount: 1,
        lastLoginDaysAgo: 0,
        isApproved: false,
        consistentLocation: false,
        consistentUsagePattern: false,
      };

      const score = calculateDeviceTrustScore(factors);

      expect(score).toBeLessThan(20);
    });

    it('should penalize inconsistent location usage', () => {
      const baseFactors: TrustFactors = {
        ageInDays: 30,
        loginCount: 50,
        lastLoginDaysAgo: 1,
        isApproved: true,
        consistentLocation: true,
        consistentUsagePattern: true,
      };

      const scoreConsistent = calculateDeviceTrustScore(baseFactors);
      const scoreInconsistent = calculateDeviceTrustScore({
        ...baseFactors,
        consistentLocation: false,
      });

      expect(scoreConsistent).toBeGreaterThan(scoreInconsistent);
      expect(scoreConsistent - scoreInconsistent).toBeGreaterThanOrEqual(10);
    });

    it('should significantly increase trust for approved devices', () => {
      const baseFactors: TrustFactors = {
        ageInDays: 30,
        loginCount: 20,
        lastLoginDaysAgo: 1,
        isApproved: false,
        consistentLocation: true,
        consistentUsagePattern: true,
      };

      const scoreUnapproved = calculateDeviceTrustScore(baseFactors);
      const scoreApproved = calculateDeviceTrustScore({
        ...baseFactors,
        isApproved: true,
      });

      expect(scoreApproved).toBeGreaterThan(scoreUnapproved);
      expect(scoreApproved - scoreUnapproved).toBeGreaterThanOrEqual(20);
    });

    it('should decrease trust score for stale devices', () => {
      const recentDevice: TrustFactors = {
        ageInDays: 60,
        loginCount: 100,
        lastLoginDaysAgo: 2,
        isApproved: true,
        consistentLocation: true,
        consistentUsagePattern: true,
      };

      const staleDevice: TrustFactors = {
        ...recentDevice,
        lastLoginDaysAgo: 60,
      };

      const recentScore = calculateDeviceTrustScore(recentDevice);
      const staleScore = calculateDeviceTrustScore(staleDevice);

      expect(recentScore).toBeGreaterThan(staleScore);
    });
  });

  describe('Device Approval Workflow', () => {
    let registry: DeviceRegistry;

    beforeEach(() => {
      registry = new DeviceRegistry();
    });

    it('should create pending device on initial registration', async () => {
      const device = await registry.registerDevice(
        'user123',
        'fp_pending',
        { name: 'New Device', os: 'OS', browser: 'Browser' },
        'tenant1'
      );

      expect(device.status).toBe('pending');
    });

    it('should approve device and update status', async () => {
      const device = await registry.registerDevice(
        'user123',
        'fp_approve',
        { name: 'Device to Approve', os: 'OS', browser: 'Browser' },
        'tenant1'
      );

      await registry.approveDevice(device.id, 'admin@company.com');
      const approved = await registry.getDevice(device.id);

      expect(approved?.status).toBe('approved');
      expect(approved?.approvedBy).toBe('admin@company.com');
      expect(approved?.approvedAt).toBeDefined();
    });

    it('should revoke device and update status', async () => {
      const device = await registry.registerDevice(
        'user123',
        'fp_revoke',
        { name: 'Device to Revoke', os: 'OS', browser: 'Browser' },
        'tenant1'
      );

      await registry.approveDevice(device.id, 'admin@company.com');
      await registry.revokeDevice(device.id, 'security@company.com', 'Compromised device');

      const revoked = await registry.getDevice(device.id);

      expect(revoked?.status).toBe('revoked');
      expect(revoked?.revokedBy).toBe('security@company.com');
      expect(revoked?.revokedReason).toBe('Compromised device');
    });

    it('should list pending approval requests', async () => {
      await registry.registerDevice('user1', 'fp1', { name: 'D1', os: 'OS', browser: 'B' }, 'tenant1');
      await registry.registerDevice('user2', 'fp2', { name: 'D2', os: 'OS', browser: 'B' }, 'tenant1');
      await registry.registerDevice('user3', 'fp3', { name: 'D3', os: 'OS', browser: 'B' }, 'tenant1');

      const pending = await registry.getPendingApprovals('tenant1');

      expect(pending).toHaveLength(3);
      expect(pending.every(d => d.status === 'pending')).toBe(true);
    });

    it('should reject device approval', async () => {
      const device = await registry.registerDevice(
        'user123',
        'fp_reject',
        { name: 'Suspicious Device', os: 'Unknown', browser: 'Unknown' },
        'tenant1'
      );

      await registry.denyDevice(device.id, 'admin@company.com', 'Unrecognized device');

      const denied = await registry.getDevice(device.id);

      expect(denied?.status).toBe('denied');
      expect(denied?.deniedBy).toBe('admin@company.com');
      expect(denied?.deniedReason).toBe('Unrecognized device');
    });
  });

  describe('Trusted Device Expiration', () => {
    let registry: DeviceRegistry;

    beforeEach(() => {
      registry = new DeviceRegistry();
    });

    it('should expire trusted devices after 90 days of inactivity', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 91);

      const device = await registry.registerDevice(
        'user123',
        'fp_expire',
        { name: 'Old Device', os: 'OS', browser: 'Browser' },
        'tenant1'
      );
      await registry.approveDevice(device.id, 'admin@company.com');

      // Manually set last seen to old date for testing
      await registry.setDeviceLastSeen(device.id, oldDate);

      const expiredCount = await registry.cleanupExpiredDevices(90);

      expect(expiredCount).toBe(1);
      const updated = await registry.getDevice(device.id);
      expect(updated?.status).toBe('expired');
    });

    it('should not expire recently used trusted devices', async () => {
      const device = await registry.registerDevice(
        'user123',
        'fp_recent',
        { name: 'Recent Device', os: 'OS', browser: 'Browser' },
        'tenant1'
      );
      await registry.approveDevice(device.id, 'admin@company.com');

      // Device was just used, should not expire
      const expiredCount = await registry.cleanupExpiredDevices(90);

      expect(expiredCount).toBe(0);
      const updated = await registry.getDevice(device.id);
      expect(updated?.status).toBe('approved');
    });

    it('should use custom expiration days when provided', async () => {
      const dateFortyDaysAgo = new Date();
      dateFortyDaysAgo.setDate(dateFortyDaysAgo.getDate() - 40);

      const device = await registry.registerDevice(
        'user123',
        'fp_custom_expire',
        { name: 'Test Device', os: 'OS', browser: 'Browser' },
        'tenant1'
      );
      await registry.approveDevice(device.id, 'admin@company.com');
      await registry.setDeviceLastSeen(device.id, dateFortyDaysAgo);

      // Should not expire with 90 day window
      let expiredCount = await registry.cleanupExpiredDevices(90);
      expect(expiredCount).toBe(0);

      // Should expire with 30 day window
      expiredCount = await registry.cleanupExpiredDevices(30);
      expect(expiredCount).toBe(1);
    });
  });

  describe('Multiple Devices Per User', () => {
    let registry: DeviceRegistry;

    beforeEach(() => {
      registry = new DeviceRegistry();
    });

    it('should support multiple devices for same user', async () => {
      const userId = 'multi_device_user';
      const tenantId = 'tenant1';

      await registry.registerDevice(userId, 'fp_laptop', { name: 'Work Laptop', os: 'macOS', browser: 'Chrome' }, tenantId);
      await registry.registerDevice(userId, 'fp_phone', { name: 'iPhone', os: 'iOS', browser: 'Safari' }, tenantId);
      await registry.registerDevice(userId, 'fp_tablet', { name: 'iPad', os: 'iPadOS', browser: 'Safari' }, tenantId);

      const devices = await registry.getDevicesForUser(userId);

      expect(devices).toHaveLength(3);
    });

    it('should track device status independently per device', async () => {
      const userId = 'status_test_user';
      const tenantId = 'tenant1';

      const laptop = await registry.registerDevice(userId, 'fp_lap', { name: 'Laptop', os: 'macOS', browser: 'Chrome' }, tenantId);
      const phone = await registry.registerDevice(userId, 'fp_ph', { name: 'Phone', os: 'iOS', browser: 'Safari' }, tenantId);

      await registry.approveDevice(laptop.id, 'admin@company.com');
      // Phone remains pending

      const devices = await registry.getDevicesForUser(userId);
      const laptopDevice = devices.find(d => d.id === laptop.id);
      const phoneDevice = devices.find(d => d.id === phone.id);

      expect(laptopDevice?.status).toBe('approved');
      expect(phoneDevice?.status).toBe('pending');
    });

    it('should calculate trust scores independently per device', async () => {
      const userId = 'trust_test_user';
      const tenantId = 'tenant1';

      const oldDevice = await registry.registerDevice(
        userId,
        'fp_old',
        { name: 'Old Device', os: 'OS', browser: 'Browser' },
        tenantId
      );
      await registry.approveDevice(oldDevice.id, 'admin@company.com');
      // Simulate many logins
      for (let i = 0; i < 50; i++) {
        await registry.updateDeviceActivity(oldDevice.id);
      }

      const newDevice = await registry.registerDevice(
        userId,
        'fp_new',
        { name: 'New Device', os: 'OS', browser: 'Browser' },
        tenantId
      );

      const oldTrust = await registry.checkDeviceTrust(userId, 'fp_old');
      const newTrust = await registry.checkDeviceTrust(userId, 'fp_new');

      expect(oldTrust.score).toBeGreaterThan(newTrust.score);
      expect(oldTrust.isTrusted).toBe(true);
      expect(newTrust.isTrusted).toBe(false);
    });
  });

  describe('Device Metadata Storage', () => {
    let registry: DeviceRegistry;

    beforeEach(() => {
      registry = new DeviceRegistry();
    });

    it('should store complete device metadata', async () => {
      const metadata: DeviceMetadata = {
        name: 'Work MacBook Pro',
        os: 'macOS Sonoma 14.2',
        browser: 'Chrome 120.0.6099.199',
        ipAddress: '192.168.1.100',
        location: {
          country: 'United States',
          city: 'New York',
          lat: 40.7128,
          lng: -74.0060,
        },
      };

      const device = await registry.registerDevice('user123', 'fp_meta', metadata, 'tenant1');

      expect(device.metadata.name).toBe('Work MacBook Pro');
      expect(device.metadata.os).toBe('macOS Sonoma 14.2');
      expect(device.metadata.browser).toBe('Chrome 120.0.6099.199');
      expect(device.metadata.ipAddress).toBe('192.168.1.100');
      expect(device.metadata.location?.country).toBe('United States');
    });

    it('should track first seen and last seen timestamps', async () => {
      const device = await registry.registerDevice(
        'user123',
        'fp_time',
        { name: 'Test', os: 'OS', browser: 'Browser' },
        'tenant1'
      );

      expect(device.firstSeen).toBeInstanceOf(Date);
      expect(device.lastSeen).toBeInstanceOf(Date);
      expect(device.firstSeen.getTime()).toBeLessThanOrEqual(device.lastSeen.getTime());
    });

    it('should update metadata on device activity', async () => {
      const device = await registry.registerDevice(
        'user123',
        'fp_update_meta',
        { name: 'Device', os: 'Windows 10', browser: 'Chrome 119' },
        'tenant1'
      );

      await registry.updateDeviceActivity(device.id, {
        browser: 'Chrome 120',
        ipAddress: '10.0.0.50',
      });

      const updated = await registry.getDevice(device.id);

      expect(updated?.metadata.browser).toBe('Chrome 120');
      expect(updated?.metadata.ipAddress).toBe('10.0.0.50');
      expect(updated?.metadata.os).toBe('Windows 10'); // Unchanged
    });
  });

  describe('Tenant Isolation', () => {
    let registry: DeviceRegistry;

    beforeEach(() => {
      registry = new DeviceRegistry();
    });

    it('should isolate devices by tenant', async () => {
      await registry.registerDevice('user1', 'fp1', { name: 'T1 Device', os: 'OS', browser: 'B' }, 'tenant1');
      await registry.registerDevice('user1', 'fp2', { name: 'T2 Device', os: 'OS', browser: 'B' }, 'tenant2');

      const tenant1Devices = await registry.getDevicesForTenant('tenant1');
      const tenant2Devices = await registry.getDevicesForTenant('tenant2');

      expect(tenant1Devices).toHaveLength(1);
      expect(tenant1Devices[0].metadata.name).toBe('T1 Device');
      expect(tenant2Devices).toHaveLength(1);
      expect(tenant2Devices[0].metadata.name).toBe('T2 Device');
    });

    it('should not return devices from other tenants when querying user devices', async () => {
      // Same user ID in different tenants (edge case)
      await registry.registerDevice('shared_user', 'fp_t1', { name: 'Tenant1 Device', os: 'OS', browser: 'B' }, 'tenant1');
      await registry.registerDevice('shared_user', 'fp_t2', { name: 'Tenant2 Device', os: 'OS', browser: 'B' }, 'tenant2');

      const tenant1Devices = await registry.getDevicesForUser('shared_user', 'tenant1');
      const tenant2Devices = await registry.getDevicesForUser('shared_user', 'tenant2');

      expect(tenant1Devices).toHaveLength(1);
      expect(tenant1Devices[0].tenantId).toBe('tenant1');
      expect(tenant2Devices).toHaveLength(1);
      expect(tenant2Devices[0].tenantId).toBe('tenant2');
    });

    it('should scope pending approvals to tenant', async () => {
      await registry.registerDevice('user1', 'fp1', { name: 'D1', os: 'OS', browser: 'B' }, 'tenant1');
      await registry.registerDevice('user2', 'fp2', { name: 'D2', os: 'OS', browser: 'B' }, 'tenant1');
      await registry.registerDevice('user3', 'fp3', { name: 'D3', os: 'OS', browser: 'B' }, 'tenant2');

      const tenant1Pending = await registry.getPendingApprovals('tenant1');
      const tenant2Pending = await registry.getPendingApprovals('tenant2');

      expect(tenant1Pending).toHaveLength(2);
      expect(tenant2Pending).toHaveLength(1);
    });

    it('should scope device expiration cleanup to tenant', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 100);

      const device1 = await registry.registerDevice('user1', 'fp_exp1', { name: 'D1', os: 'OS', browser: 'B' }, 'tenant1');
      const device2 = await registry.registerDevice('user2', 'fp_exp2', { name: 'D2', os: 'OS', browser: 'B' }, 'tenant2');

      await registry.approveDevice(device1.id, 'admin');
      await registry.approveDevice(device2.id, 'admin');
      await registry.setDeviceLastSeen(device1.id, oldDate);
      await registry.setDeviceLastSeen(device2.id, oldDate);

      const expiredCount = await registry.cleanupExpiredDevices(90, 'tenant1');

      expect(expiredCount).toBe(1);

      const d1 = await registry.getDevice(device1.id);
      const d2 = await registry.getDevice(device2.id);

      expect(d1?.status).toBe('expired');
      expect(d2?.status).toBe('approved'); // Not affected
    });
  });

  describe('Device Trust Check', () => {
    let registry: DeviceRegistry;

    beforeEach(() => {
      registry = new DeviceRegistry();
    });

    it('should return trust information for known device', async () => {
      const device = await registry.registerDevice(
        'user123',
        'fp_trust_check',
        { name: 'Trusted Device', os: 'OS', browser: 'Browser' },
        'tenant1'
      );
      await registry.approveDevice(device.id, 'admin@company.com');

      const trust = await registry.checkDeviceTrust('user123', 'fp_trust_check');

      expect(trust).toBeDefined();
      expect(trust.deviceId).toBe(device.id);
      expect(trust.isTrusted).toBe(true);
      expect(trust.score).toBeGreaterThan(0);
      expect(trust.status).toBe('approved');
    });

    it('should return untrusted status for unknown device', async () => {
      const trust = await registry.checkDeviceTrust('user123', 'fp_unknown_device');

      expect(trust.isTrusted).toBe(false);
      expect(trust.deviceId).toBeNull();
      expect(trust.status).toBe('unknown');
      expect(trust.score).toBe(0);
    });

    it('should return pending trust status for unapproved device', async () => {
      await registry.registerDevice(
        'user123',
        'fp_pending_trust',
        { name: 'Pending Device', os: 'OS', browser: 'Browser' },
        'tenant1'
      );

      const trust = await registry.checkDeviceTrust('user123', 'fp_pending_trust');

      expect(trust.isTrusted).toBe(false);
      expect(trust.status).toBe('pending');
    });
  });
});
