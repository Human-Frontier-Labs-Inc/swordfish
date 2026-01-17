/**
 * Impossible Travel Detection Tests
 *
 * Tests for detecting physically impossible travel based on login locations and times.
 * Flags scenarios where a user logs in from locations that would require travel
 * speeds exceeding 500 mph (impossible without supersonic flight).
 */

import {
  calculateDistance,
  calculateTimeDifference,
  calculateTravelSpeed,
  isImpossibleTravel,
  checkVPNOrProxy,
  isKnownTravelPattern,
  addKnownTravelPattern,
  clearKnownTravelPatterns,
  generateImpossibleTravelAlert,
  calculateRiskScore,
  ImpossibleTravelDetector,
  type LoginLocation,
  type TravelPattern,
  type ImpossibleTravelAlert,
  type Coordinates,
  type TravelAnalysis,
} from '@/lib/ato/impossible-travel';
import { calculateHaversineDistance } from '@/lib/ato/distance-calculator';

describe('Impossible Travel Detection', () => {
  describe('Distance Calculation (Haversine)', () => {
    it('should calculate distance between two coordinates correctly', () => {
      // New York to Los Angeles
      const nyc = { lat: 40.7128, lng: -74.0060 };
      const la = { lat: 34.0522, lng: -118.2437 };

      const distance = calculateHaversineDistance(nyc.lat, nyc.lng, la.lat, la.lng);

      // Actual distance is ~2,451 miles
      expect(distance).toBeGreaterThan(2400);
      expect(distance).toBeLessThan(2500);
    });

    it('should return 0 for same coordinates', () => {
      const point = { lat: 51.5074, lng: -0.1278 };

      const distance = calculateHaversineDistance(point.lat, point.lng, point.lat, point.lng);

      expect(distance).toBe(0);
    });

    it('should calculate short distances accurately', () => {
      // Two points in Manhattan (~3.5 miles apart)
      const timesSquare = { lat: 40.7580, lng: -73.9855 };
      const wallStreet = { lat: 40.7074, lng: -74.0113 };

      const distance = calculateHaversineDistance(
        timesSquare.lat, timesSquare.lng,
        wallStreet.lat, wallStreet.lng
      );

      expect(distance).toBeGreaterThan(3);
      expect(distance).toBeLessThan(5);
    });

    it('should handle antipodal points (maximum distance)', () => {
      // North Pole to South Pole
      const northPole = { lat: 90, lng: 0 };
      const southPole = { lat: -90, lng: 0 };

      const distance = calculateHaversineDistance(
        northPole.lat, northPole.lng,
        southPole.lat, southPole.lng
      );

      // Half Earth circumference ~12,430 miles
      expect(distance).toBeGreaterThan(12400);
      expect(distance).toBeLessThan(12500);
    });

    it('should calculate transcontinental distances correctly', () => {
      // London to Tokyo
      const london = { lat: 51.5074, lng: -0.1278 };
      const tokyo = { lat: 35.6762, lng: 139.6503 };

      const distance = calculateHaversineDistance(
        london.lat, london.lng,
        tokyo.lat, tokyo.lng
      );

      // Actual distance is ~5,959 miles
      expect(distance).toBeGreaterThan(5900);
      expect(distance).toBeLessThan(6000);
    });

    it('should handle cross-equator distances', () => {
      // New York to Sydney
      const nyc = { lat: 40.7128, lng: -74.0060 };
      const sydney = { lat: -33.8688, lng: 151.2093 };

      const distance = calculateHaversineDistance(
        nyc.lat, nyc.lng,
        sydney.lat, sydney.lng
      );

      // Actual distance is ~9,933 miles
      expect(distance).toBeGreaterThan(9800);
      expect(distance).toBeLessThan(10100);
    });

    it('should handle negative longitudes (Western hemisphere)', () => {
      // San Francisco to Honolulu
      const sf = { lat: 37.7749, lng: -122.4194 };
      const honolulu = { lat: 21.3069, lng: -157.8583 };

      const distance = calculateHaversineDistance(
        sf.lat, sf.lng,
        honolulu.lat, honolulu.lng
      );

      // Actual distance is ~2,397 miles
      expect(distance).toBeGreaterThan(2350);
      expect(distance).toBeLessThan(2450);
    });
  });

  describe('Time Calculation', () => {
    it('should calculate time difference in hours between two logins', () => {
      const login1 = new Date('2024-01-15T10:00:00Z');
      const login2 = new Date('2024-01-15T12:30:00Z');

      const timeDiff = calculateTimeDifference(login1, login2);

      expect(timeDiff).toBe(2.5);
    });

    it('should handle logins on different days', () => {
      const login1 = new Date('2024-01-15T22:00:00Z');
      const login2 = new Date('2024-01-16T04:00:00Z');

      const timeDiff = calculateTimeDifference(login1, login2);

      expect(timeDiff).toBe(6);
    });

    it('should return absolute value for reversed times', () => {
      const login1 = new Date('2024-01-15T12:00:00Z');
      const login2 = new Date('2024-01-15T10:00:00Z');

      const timeDiff = calculateTimeDifference(login1, login2);

      expect(timeDiff).toBe(2);
    });

    it('should handle very small time differences (minutes)', () => {
      const login1 = new Date('2024-01-15T10:00:00Z');
      const login2 = new Date('2024-01-15T10:15:00Z');

      const timeDiff = calculateTimeDifference(login1, login2);

      expect(timeDiff).toBe(0.25);
    });

    it('should handle timezone-agnostic calculations (UTC)', () => {
      // Both timestamps are in UTC, so no timezone issues
      const login1 = new Date('2024-01-15T23:30:00Z');
      const login2 = new Date('2024-01-16T00:30:00Z');

      const timeDiff = calculateTimeDifference(login1, login2);

      expect(timeDiff).toBe(1);
    });

    it('should handle same timestamp', () => {
      const login1 = new Date('2024-01-15T10:00:00Z');
      const login2 = new Date('2024-01-15T10:00:00Z');

      const timeDiff = calculateTimeDifference(login1, login2);

      expect(timeDiff).toBe(0);
    });
  });

  describe('Travel Speed Calculation', () => {
    it('should calculate travel speed correctly', () => {
      const distance = 500; // miles
      const time = 2; // hours

      const speed = calculateTravelSpeed(distance, time);

      expect(speed).toBe(250); // mph
    });

    it('should handle zero time by returning Infinity', () => {
      const distance = 100;
      const time = 0;

      const speed = calculateTravelSpeed(distance, time);

      expect(speed).toBe(Infinity);
    });

    it('should handle zero distance correctly', () => {
      const distance = 0;
      const time = 2;

      const speed = calculateTravelSpeed(distance, time);

      expect(speed).toBe(0);
    });

    it('should calculate realistic flight speeds', () => {
      // Commercial flight speed is typically 500-600 mph
      const distance = 2400; // NYC to LA
      const time = 5; // 5 hour flight

      const speed = calculateTravelSpeed(distance, time);

      expect(speed).toBe(480);
      expect(speed).toBeLessThan(500); // Within commercial flight speed
    });
  });

  describe('Impossible Travel Detection', () => {
    it('should flag travel exceeding 500 mph as impossible', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128, // NYC
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T12:00:00Z'), // 2 hours later
        lat: 34.0522, // LA
        lng: -118.2437,
        ip: '192.168.1.2',
      };

      // NYC to LA is ~2,451 miles, in 2 hours = ~1,225 mph (impossible)
      const result = isImpossibleTravel(login1, login2);

      expect(result.isImpossible).toBe(true);
      expect(result.speed).toBeGreaterThan(1000);
    });

    it('should not flag reasonable travel speeds', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T16:00:00Z'), // 6 hours later
        lat: 34.0522,
        lng: -118.2437,
        ip: '192.168.1.2',
      };

      // ~2,451 miles in 6 hours = ~408 mph (possible via commercial flight)
      const result = isImpossibleTravel(login1, login2);

      expect(result.isImpossible).toBe(false);
    });

    it('should not flag same location logins', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:05:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.2',
      };

      const result = isImpossibleTravel(login1, login2);

      expect(result.isImpossible).toBe(false);
      expect(result.speed).toBe(0);
    });

    it('should handle custom speed threshold', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128, // NYC
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T15:00:00Z'), // 5 hours later
        lat: 34.0522, // LA
        lng: -118.2437,
        ip: '192.168.1.2',
      };

      // ~2,451 miles in 5 hours = ~490 mph
      // With default threshold (500), this is not impossible
      const resultDefault = isImpossibleTravel(login1, login2);
      expect(resultDefault.isImpossible).toBe(false);

      // With lower threshold (400), this is impossible
      const resultLower = isImpossibleTravel(login1, login2, 400);
      expect(resultLower.isImpossible).toBe(true);
    });

    it('should handle missing geo data gracefully', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:30:00Z'),
        lat: 51.5074,
        lng: -0.1278,
        ip: '192.168.2.1',
      };

      const result = isImpossibleTravel(login1, login2);

      expect(result.isImpossible).toBe(false);
      expect(result.missingGeoData).toBe(true);
    });
  });

  describe('VPN/Proxy Detection', () => {
    it('should detect known datacenter IP ranges', () => {
      const knownDatacenterIPs = [
        '104.16.0.1',    // Cloudflare
        '35.192.0.1',    // Google Cloud
        '52.0.0.1',      // AWS
        '13.64.0.1',     // Azure
      ];

      for (const ip of knownDatacenterIPs) {
        const result = checkVPNOrProxy(ip);
        expect(result.isVPN).toBe(true);
        expect(result.provider).toBeDefined();
      }
    });

    it('should not flag residential IPs as VPN', () => {
      const residentialIP = '98.234.56.78'; // Typical residential

      const result = checkVPNOrProxy(residentialIP);

      expect(result.isVPN).toBe(false);
    });

    it('should identify specific VPN providers', () => {
      const nordVpnIP = '185.202.220.1'; // NordVPN range

      const result = checkVPNOrProxy(nordVpnIP);

      expect(result.isVPN).toBe(true);
      expect(result.provider).toContain('NordVPN');
    });

    it('should handle DigitalOcean datacenter IPs', () => {
      const digitalOceanIP = '159.89.0.1';

      const result = checkVPNOrProxy(digitalOceanIP);

      expect(result.isVPN).toBe(true);
      expect(result.provider).toContain('DigitalOcean');
    });

    it('should return confidence score for VPN detection', () => {
      const datacenterIP = '35.192.0.1'; // Google Cloud

      const result = checkVPNOrProxy(datacenterIP);

      expect(result.confidence).toBeDefined();
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
    });
  });

  describe('Known Travel Patterns', () => {
    const userId = 'user123';

    beforeEach(() => {
      clearKnownTravelPatterns();
    });

    it('should whitelist known travel patterns', () => {
      const pattern: TravelPattern = {
        userId,
        fromLocation: { lat: 40.7128, lng: -74.0060, name: 'NYC' },
        toLocation: { lat: 34.0522, lng: -118.2437, name: 'LA' },
        frequency: 'weekly',
      };

      addKnownTravelPattern(pattern);

      const isKnown = isKnownTravelPattern(
        userId,
        { lat: 40.7128, lng: -74.0060 },
        { lat: 34.0522, lng: -118.2437 }
      );

      expect(isKnown).toBe(true);
    });

    it('should not whitelist unknown travel patterns', () => {
      const isKnown = isKnownTravelPattern(
        userId,
        { lat: 51.5074, lng: -0.1278 }, // London
        { lat: -33.8688, lng: 151.2093 } // Sydney
      );

      expect(isKnown).toBe(false);
    });

    it('should match patterns with location tolerance', () => {
      const pattern: TravelPattern = {
        userId,
        fromLocation: { lat: 40.7128, lng: -74.0060, name: 'NYC' },
        toLocation: { lat: 34.0522, lng: -118.2437, name: 'LA' },
        frequency: 'weekly',
      };

      addKnownTravelPattern(pattern);

      // Slightly different coordinates (within tolerance)
      const isKnown = isKnownTravelPattern(
        userId,
        { lat: 40.7130, lng: -74.0062 }, // ~30 meters off
        { lat: 34.0520, lng: -118.2440 }
      );

      expect(isKnown).toBe(true);
    });

    it('should match bidirectional patterns', () => {
      const pattern: TravelPattern = {
        userId,
        fromLocation: { lat: 40.7128, lng: -74.0060, name: 'NYC' },
        toLocation: { lat: 34.0522, lng: -118.2437, name: 'LA' },
        frequency: 'weekly',
      };

      addKnownTravelPattern(pattern);

      // Reverse direction (LA to NYC)
      const isKnown = isKnownTravelPattern(
        userId,
        { lat: 34.0522, lng: -118.2437 },
        { lat: 40.7128, lng: -74.0060 }
      );

      expect(isKnown).toBe(true);
    });

    it('should not match patterns for different users', () => {
      const pattern: TravelPattern = {
        userId: 'user999',
        fromLocation: { lat: 40.7128, lng: -74.0060, name: 'NYC' },
        toLocation: { lat: 34.0522, lng: -118.2437, name: 'LA' },
        frequency: 'weekly',
      };

      addKnownTravelPattern(pattern);

      const isKnown = isKnownTravelPattern(
        'differentUser',
        { lat: 40.7128, lng: -74.0060 },
        { lat: 34.0522, lng: -118.2437 }
      );

      expect(isKnown).toBe(false);
    });
  });

  describe('Alert Generation', () => {
    it('should generate alert on impossible travel detection', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:30:00Z'), // 30 min later
        lat: 51.5074, // London
        lng: -0.1278,
        ip: '192.168.2.1',
      };

      const alert = generateImpossibleTravelAlert(login1, login2);

      expect(alert).toBeDefined();
      expect(alert!.userId).toBe('user123');
      expect(alert!.severity).toBe('critical');
      expect(alert!.type).toBe('impossible_travel');
      expect(alert!.details.fromLocation).toBeDefined();
      expect(alert!.details.toLocation).toBeDefined();
      expect(alert!.details.calculatedSpeed).toBeGreaterThan(500);
    });

    it('should not generate alert for normal travel', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-16T10:00:00Z'), // 24 hours later
        lat: 51.5074,
        lng: -0.1278,
        ip: '192.168.2.1',
      };

      const alert = generateImpossibleTravelAlert(login1, login2);

      expect(alert).toBeNull();
    });

    it('should include distance and time in alert details', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:30:00Z'),
        lat: 51.5074,
        lng: -0.1278,
        ip: '192.168.2.1',
      };

      const alert = generateImpossibleTravelAlert(login1, login2);

      expect(alert!.details.distanceMiles).toBeDefined();
      expect(alert!.details.timeDifferenceHours).toBeDefined();
      expect(alert!.details.distanceMiles).toBeGreaterThan(3000);
      expect(alert!.details.timeDifferenceHours).toBe(0.5);
    });

    it('should include IP addresses in alert', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.100',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:30:00Z'),
        lat: 51.5074,
        lng: -0.1278,
        ip: '10.0.0.200',
      };

      const alert = generateImpossibleTravelAlert(login1, login2);

      expect(alert!.details.fromIP).toBe('192.168.1.100');
      expect(alert!.details.toIP).toBe('10.0.0.200');
    });
  });

  describe('Risk Score Calculation', () => {
    it('should return high risk score for extreme speed', () => {
      const speed = 5000; // mph - clearly impossible
      const isVPN = false;
      const isKnownPattern = false;

      const score = calculateRiskScore(speed, isVPN, isKnownPattern);

      expect(score).toBeGreaterThanOrEqual(90);
    });

    it('should reduce risk score for VPN usage', () => {
      const speed = 1000;
      const isVPN = true;
      const isKnownPattern = false;

      const score = calculateRiskScore(speed, isVPN, isKnownPattern);

      // VPN reduces confidence, so lower risk score
      expect(score).toBeLessThan(70);
    });

    it('should significantly reduce risk for known travel patterns', () => {
      const speed = 1000;
      const isVPN = false;
      const isKnownPattern = true;

      const score = calculateRiskScore(speed, isVPN, isKnownPattern);

      expect(score).toBeLessThan(30);
    });

    it('should return 0 for non-impossible speeds', () => {
      const speed = 300; // mph - possible by plane
      const isVPN = false;
      const isKnownPattern = false;

      const score = calculateRiskScore(speed, isVPN, isKnownPattern);

      expect(score).toBe(0);
    });

    it('should scale risk score based on speed magnitude', () => {
      const speed600 = calculateRiskScore(600, false, false);
      const speed1000 = calculateRiskScore(1000, false, false);
      const speed2000 = calculateRiskScore(2000, false, false);

      expect(speed600).toBeLessThan(speed1000);
      expect(speed1000).toBeLessThan(speed2000);
    });

    it('should cap risk score at 100', () => {
      const score = calculateRiskScore(100000, false, false);

      expect(score).toBeLessThanOrEqual(100);
    });
  });

  describe('ImpossibleTravelDetector Class', () => {
    let detector: ImpossibleTravelDetector;

    beforeEach(() => {
      clearKnownTravelPatterns();
      detector = new ImpossibleTravelDetector();
    });

    it('should analyze login sequence and detect impossible travel', async () => {
      const logins: LoginLocation[] = [
        {
          userId: 'user123',
          timestamp: new Date('2024-01-15T10:00:00Z'),
          lat: 40.7128,
          lng: -74.0060,
          ip: '192.168.1.1',
        },
        {
          userId: 'user123',
          timestamp: new Date('2024-01-15T10:30:00Z'),
          lat: 51.5074, // London - impossible in 30 min
          lng: -0.1278,
          ip: '192.168.2.1',
        },
      ];

      const alerts = await detector.analyzeLoginSequence('user123', logins);

      expect(alerts).toHaveLength(1);
      expect(alerts[0].type).toBe('impossible_travel');
    });

    it('should handle multiple users independently', async () => {
      const user1Logins: LoginLocation[] = [
        {
          userId: 'user1',
          timestamp: new Date('2024-01-15T10:00:00Z'),
          lat: 40.7128,
          lng: -74.0060,
          ip: '192.168.1.1',
        },
        {
          userId: 'user1',
          timestamp: new Date('2024-01-15T10:30:00Z'),
          lat: 51.5074,
          lng: -0.1278,
          ip: '192.168.2.1',
        },
      ];

      const user2Logins: LoginLocation[] = [
        {
          userId: 'user2',
          timestamp: new Date('2024-01-15T10:00:00Z'),
          lat: 40.7128,
          lng: -74.0060,
          ip: '192.168.1.3',
        },
        {
          userId: 'user2',
          timestamp: new Date('2024-01-15T18:00:00Z'), // 8 hours - possible
          lat: 51.5074,
          lng: -0.1278,
          ip: '192.168.2.3',
        },
      ];

      const alerts1 = await detector.analyzeLoginSequence('user1', user1Logins);
      const alerts2 = await detector.analyzeLoginSequence('user2', user2Logins);

      expect(alerts1).toHaveLength(1);
      expect(alerts2).toHaveLength(0);
    });

    it('should analyze login pair directly', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:30:00Z'),
        lat: 51.5074,
        lng: -0.1278,
        ip: '192.168.2.1',
      };

      const analysis = detector.analyzeLoginPair(login1, login2);

      expect(analysis.isImpossible).toBe(true);
      expect(analysis.distance).toBeGreaterThan(3000);
      expect(analysis.timeHours).toBe(0.5);
      expect(analysis.speedMph).toBeGreaterThan(6000);
    });

    it('should add and respect travel exceptions', async () => {
      // First, add a travel exception
      detector.addTravelException('user123', {
        userId: 'user123',
        fromLocation: { lat: 40.7128, lng: -74.0060, name: 'NYC' },
        toLocation: { lat: 51.5074, lng: -0.1278, name: 'London' },
        frequency: 'weekly',
      });

      const logins: LoginLocation[] = [
        {
          userId: 'user123',
          timestamp: new Date('2024-01-15T10:00:00Z'),
          lat: 40.7128,
          lng: -74.0060,
          ip: '192.168.1.1',
        },
        {
          userId: 'user123',
          timestamp: new Date('2024-01-15T10:30:00Z'),
          lat: 51.5074,
          lng: -0.1278,
          ip: '192.168.2.1',
        },
      ];

      const alerts = await detector.analyzeLoginSequence('user123', logins);

      // Should still detect but with lower risk score
      expect(alerts).toHaveLength(1);
      expect(alerts[0].riskScore).toBeLessThan(30);
    });

    it('should calculate risk score for travel analysis', () => {
      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:30:00Z'),
        lat: 51.5074,
        lng: -0.1278,
        ip: '192.168.2.1',
      };

      const analysis = detector.analyzeLoginPair(login1, login2);
      const riskScore = detector.getRiskScore(analysis);

      expect(riskScore).toBeGreaterThan(80);
    });

    it('should handle empty login sequence', async () => {
      const alerts = await detector.analyzeLoginSequence('user123', []);

      expect(alerts).toHaveLength(0);
    });

    it('should handle single login (no pair to compare)', async () => {
      const logins: LoginLocation[] = [
        {
          userId: 'user123',
          timestamp: new Date('2024-01-15T10:00:00Z'),
          lat: 40.7128,
          lng: -74.0060,
          ip: '192.168.1.1',
        },
      ];

      const alerts = await detector.analyzeLoginSequence('user123', logins);

      expect(alerts).toHaveLength(0);
    });

    it('should detect multiple impossible travels in sequence', async () => {
      const logins: LoginLocation[] = [
        {
          userId: 'user123',
          timestamp: new Date('2024-01-15T10:00:00Z'),
          lat: 40.7128, // NYC
          lng: -74.0060,
          ip: '192.168.1.1',
        },
        {
          userId: 'user123',
          timestamp: new Date('2024-01-15T10:30:00Z'),
          lat: 51.5074, // London - impossible
          lng: -0.1278,
          ip: '192.168.2.1',
        },
        {
          userId: 'user123',
          timestamp: new Date('2024-01-15T11:00:00Z'),
          lat: 35.6762, // Tokyo - also impossible
          lng: 139.6503,
          ip: '192.168.3.1',
        },
      ];

      const alerts = await detector.analyzeLoginSequence('user123', logins);

      expect(alerts).toHaveLength(2);
    });

    it('should configure custom speed threshold', () => {
      const customDetector = new ImpossibleTravelDetector({ speedThresholdMph: 400 });

      const login1: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T10:00:00Z'),
        lat: 40.7128,
        lng: -74.0060,
        ip: '192.168.1.1',
      };

      const login2: LoginLocation = {
        userId: 'user123',
        timestamp: new Date('2024-01-15T15:00:00Z'), // 5 hours
        lat: 34.0522, // LA - ~490 mph
        lng: -118.2437,
        ip: '192.168.1.2',
      };

      const analysis = customDetector.analyzeLoginPair(login1, login2);

      expect(analysis.isImpossible).toBe(true); // With 400 mph threshold
    });
  });

  describe('Batch Analysis', () => {
    let detector: ImpossibleTravelDetector;

    beforeEach(() => {
      detector = new ImpossibleTravelDetector();
    });

    it('should analyze login history for multiple users in batch', async () => {
      const loginHistory = new Map<string, LoginLocation[]>();

      loginHistory.set('user1', [
        {
          userId: 'user1',
          timestamp: new Date('2024-01-15T10:00:00Z'),
          lat: 40.7128,
          lng: -74.0060,
          ip: '192.168.1.1',
        },
        {
          userId: 'user1',
          timestamp: new Date('2024-01-15T10:30:00Z'),
          lat: 51.5074, // Impossible
          lng: -0.1278,
          ip: '192.168.2.1',
        },
      ]);

      loginHistory.set('user2', [
        {
          userId: 'user2',
          timestamp: new Date('2024-01-15T10:00:00Z'),
          lat: 40.7128,
          lng: -74.0060,
          ip: '192.168.1.3',
        },
        {
          userId: 'user2',
          timestamp: new Date('2024-01-15T18:00:00Z'), // 8 hours - possible
          lat: 51.5074,
          lng: -0.1278,
          ip: '192.168.2.3',
        },
      ]);

      const allAlerts: ImpossibleTravelAlert[] = [];
      for (const [userId, logins] of loginHistory) {
        const alerts = await detector.analyzeLoginSequence(userId, logins);
        allAlerts.push(...alerts);
      }

      expect(allAlerts).toHaveLength(1);
      expect(allAlerts[0].userId).toBe('user1');
    });
  });
});
