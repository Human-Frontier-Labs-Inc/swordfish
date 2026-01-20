/**
 * Impossible Travel Detection Module
 *
 * Phase 2.2: Detects physically impossible travel based on login locations and times.
 * Flags scenarios where a user logs in from locations that would require travel
 * speeds exceeding 500 mph (impossible without supersonic flight).
 */

import { nanoid } from 'nanoid';
import { calculateHaversineDistance, areCoordinatesNearby } from './distance-calculator';

/**
 * Default speed threshold for impossible travel (in mph)
 * Commercial flights typically cruise at 500-600 mph, so 500 is a reasonable threshold
 */
const DEFAULT_SPEED_THRESHOLD_MPH = 500;

/**
 * Location tolerance for matching known patterns (in miles)
 */
const LOCATION_TOLERANCE_MILES = 50;

/**
 * Coordinates interface
 */
export interface Coordinates {
  lat: number;
  lng: number;
}

/**
 * Location with optional name
 */
export interface NamedLocation extends Coordinates {
  name?: string;
}

/**
 * Login location information
 */
export interface LoginLocation {
  userId: string;
  timestamp: Date;
  lat?: number;
  lng?: number;
  ip: string;
  city?: string;
  country?: string;
}

/**
 * Travel pattern for whitelisting
 */
export interface TravelPattern {
  userId: string;
  fromLocation: NamedLocation;
  toLocation: NamedLocation;
  frequency: 'daily' | 'weekly' | 'monthly' | 'occasional';
}

/**
 * Result of impossible travel check
 */
export interface ImpossibleTravelResult {
  isImpossible: boolean;
  speed: number;
  distance?: number;
  timeHours?: number;
  missingGeoData?: boolean;
}

/**
 * Travel analysis result
 */
export interface TravelAnalysis {
  isImpossible: boolean;
  distance: number;
  timeHours: number;
  speedMph: number;
  missingGeoData: boolean;
  fromLogin: LoginLocation;
  toLogin: LoginLocation;
  isVPN: boolean;
  isKnownPattern: boolean;
}

/**
 * VPN/Proxy check result
 */
export interface VPNCheckResult {
  isVPN: boolean;
  provider?: string;
  confidence: number;
}

/**
 * Alert details
 */
export interface AlertDetails {
  fromLocation: { lat: number; lng: number; city?: string; country?: string };
  toLocation: { lat: number; lng: number; city?: string; country?: string };
  calculatedSpeed: number;
  distanceMiles: number;
  timeDifferenceHours: number;
  fromIP: string;
  toIP: string;
  fromTimestamp: string;
  toTimestamp: string;
}

/**
 * Impossible travel alert
 */
export interface ImpossibleTravelAlert {
  id: string;
  type: 'impossible_travel';
  userId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
  details: AlertDetails;
  riskScore: number;
  isVPNSuspected: boolean;
  isKnownPattern: boolean;
}

/**
 * Detector configuration
 */
export interface DetectorConfig {
  speedThresholdMph?: number;
  locationToleranceMiles?: number;
}

// In-memory storage for known travel patterns (would be database in production)
const knownTravelPatterns: Map<string, TravelPattern[]> = new Map();

/**
 * Known datacenter and VPN provider IP ranges
 * This is a simplified version - in production, use a proper IP intelligence service
 */
const DATACENTER_IP_RANGES: Array<{ prefix: string; provider: string }> = [
  // Cloudflare
  { prefix: '104.16.', provider: 'Cloudflare' },
  { prefix: '104.17.', provider: 'Cloudflare' },
  { prefix: '104.18.', provider: 'Cloudflare' },
  { prefix: '104.19.', provider: 'Cloudflare' },
  { prefix: '104.20.', provider: 'Cloudflare' },
  { prefix: '104.21.', provider: 'Cloudflare' },
  { prefix: '104.22.', provider: 'Cloudflare' },
  { prefix: '104.23.', provider: 'Cloudflare' },
  { prefix: '104.24.', provider: 'Cloudflare' },
  { prefix: '104.25.', provider: 'Cloudflare' },
  // Google Cloud
  { prefix: '35.192.', provider: 'Google Cloud' },
  { prefix: '35.193.', provider: 'Google Cloud' },
  { prefix: '35.194.', provider: 'Google Cloud' },
  { prefix: '35.195.', provider: 'Google Cloud' },
  { prefix: '35.196.', provider: 'Google Cloud' },
  { prefix: '35.197.', provider: 'Google Cloud' },
  { prefix: '35.198.', provider: 'Google Cloud' },
  { prefix: '35.199.', provider: 'Google Cloud' },
  { prefix: '35.200.', provider: 'Google Cloud' },
  { prefix: '35.201.', provider: 'Google Cloud' },
  { prefix: '35.202.', provider: 'Google Cloud' },
  { prefix: '35.203.', provider: 'Google Cloud' },
  { prefix: '35.204.', provider: 'Google Cloud' },
  { prefix: '35.205.', provider: 'Google Cloud' },
  { prefix: '35.206.', provider: 'Google Cloud' },
  { prefix: '35.207.', provider: 'Google Cloud' },
  // AWS
  { prefix: '52.0.', provider: 'AWS' },
  { prefix: '52.1.', provider: 'AWS' },
  { prefix: '52.2.', provider: 'AWS' },
  { prefix: '52.3.', provider: 'AWS' },
  { prefix: '52.4.', provider: 'AWS' },
  { prefix: '52.5.', provider: 'AWS' },
  { prefix: '52.6.', provider: 'AWS' },
  { prefix: '52.7.', provider: 'AWS' },
  { prefix: '52.8.', provider: 'AWS' },
  { prefix: '52.9.', provider: 'AWS' },
  { prefix: '54.', provider: 'AWS' },
  // Azure
  { prefix: '13.64.', provider: 'Azure' },
  { prefix: '13.65.', provider: 'Azure' },
  { prefix: '13.66.', provider: 'Azure' },
  { prefix: '13.67.', provider: 'Azure' },
  { prefix: '13.68.', provider: 'Azure' },
  { prefix: '13.69.', provider: 'Azure' },
  { prefix: '13.70.', provider: 'Azure' },
  { prefix: '13.71.', provider: 'Azure' },
  { prefix: '13.72.', provider: 'Azure' },
  { prefix: '13.73.', provider: 'Azure' },
  { prefix: '40.', provider: 'Azure' },
  // DigitalOcean
  { prefix: '159.89.', provider: 'DigitalOcean' },
  { prefix: '159.65.', provider: 'DigitalOcean' },
  { prefix: '167.99.', provider: 'DigitalOcean' },
  { prefix: '167.71.', provider: 'DigitalOcean' },
  { prefix: '206.189.', provider: 'DigitalOcean' },
  { prefix: '209.97.', provider: 'DigitalOcean' },
  // NordVPN
  { prefix: '185.202.220.', provider: 'NordVPN' },
  { prefix: '185.202.221.', provider: 'NordVPN' },
  { prefix: '185.202.222.', provider: 'NordVPN' },
  { prefix: '185.202.223.', provider: 'NordVPN' },
  { prefix: '89.187.161.', provider: 'NordVPN' },
  { prefix: '89.187.162.', provider: 'NordVPN' },
  { prefix: '89.187.163.', provider: 'NordVPN' },
  // ExpressVPN
  { prefix: '209.205.', provider: 'ExpressVPN' },
  // Vultr
  { prefix: '45.32.', provider: 'Vultr' },
  { prefix: '45.63.', provider: 'Vultr' },
  { prefix: '45.76.', provider: 'Vultr' },
  { prefix: '45.77.', provider: 'Vultr' },
  // Linode
  { prefix: '45.33.', provider: 'Linode' },
  { prefix: '45.56.', provider: 'Linode' },
  { prefix: '45.79.', provider: 'Linode' },
];

/**
 * Calculate distance between two coordinates (wrapper for Haversine)
 */
export function calculateDistance(coord1: Coordinates, coord2: Coordinates): number {
  return calculateHaversineDistance(coord1.lat, coord1.lng, coord2.lat, coord2.lng);
}

/**
 * Calculate time difference between two dates in hours
 */
export function calculateTimeDifference(time1: Date, time2: Date): number {
  const diffMs = Math.abs(time2.getTime() - time1.getTime());
  return diffMs / (1000 * 60 * 60); // Convert to hours
}

/**
 * Calculate travel speed given distance and time
 */
export function calculateTravelSpeed(distanceMiles: number, timeHours: number): number {
  if (timeHours === 0) {
    return Infinity;
  }
  return distanceMiles / timeHours;
}

/**
 * Check if travel between two logins is impossible
 */
export function isImpossibleTravel(
  login1: LoginLocation,
  login2: LoginLocation,
  speedThreshold: number = DEFAULT_SPEED_THRESHOLD_MPH
): ImpossibleTravelResult {
  // Check if we have geo data for both logins
  if (
    login1.lat === undefined ||
    login1.lng === undefined ||
    login2.lat === undefined ||
    login2.lng === undefined
  ) {
    return {
      isImpossible: false,
      speed: 0,
      missingGeoData: true,
    };
  }

  const distance = calculateHaversineDistance(login1.lat, login1.lng, login2.lat, login2.lng);

  const timeHours = calculateTimeDifference(login1.timestamp, login2.timestamp);

  const speed = calculateTravelSpeed(distance, timeHours);

  return {
    isImpossible: speed > speedThreshold,
    speed,
    distance,
    timeHours,
  };
}

/**
 * Check if an IP is from a known VPN or datacenter
 */
export function checkVPNOrProxy(ip: string): VPNCheckResult {
  for (const range of DATACENTER_IP_RANGES) {
    if (ip.startsWith(range.prefix)) {
      return {
        isVPN: true,
        provider: range.provider,
        confidence: 0.85, // High confidence for known ranges
      };
    }
  }

  return {
    isVPN: false,
    confidence: 0.7, // Moderate confidence that it's not a VPN
  };
}

/**
 * Add a known travel pattern for a user
 */
export function addKnownTravelPattern(pattern: TravelPattern): void {
  const existing = knownTravelPatterns.get(pattern.userId) || [];
  existing.push(pattern);
  knownTravelPatterns.set(pattern.userId, existing);
}

/**
 * Clear all known travel patterns (for testing)
 */
export function clearKnownTravelPatterns(): void {
  knownTravelPatterns.clear();
}

/**
 * Check if a travel pattern is known/whitelisted for a user
 */
export function isKnownTravelPattern(
  userId: string,
  from: Coordinates,
  to: Coordinates
): boolean {
  const patterns = knownTravelPatterns.get(userId);
  if (!patterns || patterns.length === 0) {
    return false;
  }

  for (const pattern of patterns) {
    // Check forward direction
    const fromMatchesFrom = areCoordinatesNearby(
      from.lat,
      from.lng,
      pattern.fromLocation.lat,
      pattern.fromLocation.lng,
      LOCATION_TOLERANCE_MILES
    );
    const toMatchesTo = areCoordinatesNearby(
      to.lat,
      to.lng,
      pattern.toLocation.lat,
      pattern.toLocation.lng,
      LOCATION_TOLERANCE_MILES
    );

    if (fromMatchesFrom && toMatchesTo) {
      return true;
    }

    // Check reverse direction (bidirectional matching)
    const fromMatchesTo = areCoordinatesNearby(
      from.lat,
      from.lng,
      pattern.toLocation.lat,
      pattern.toLocation.lng,
      LOCATION_TOLERANCE_MILES
    );
    const toMatchesFrom = areCoordinatesNearby(
      to.lat,
      to.lng,
      pattern.fromLocation.lat,
      pattern.fromLocation.lng,
      LOCATION_TOLERANCE_MILES
    );

    if (fromMatchesTo && toMatchesFrom) {
      return true;
    }
  }

  return false;
}

/**
 * Calculate risk score based on speed, VPN usage, and known patterns
 */
export function calculateRiskScore(
  speedMph: number,
  isVPN: boolean,
  isKnownPattern: boolean
): number {
  // No risk if speed is possible
  if (speedMph <= DEFAULT_SPEED_THRESHOLD_MPH) {
    return 0;
  }

  // Base risk score based on how far above threshold
  // Scale: 500-1000 mph = 50-70, 1000-2000 mph = 70-85, 2000+ mph = 85-100
  let baseScore: number;
  if (speedMph <= 1000) {
    baseScore = 50 + ((speedMph - 500) / 500) * 20; // 50-70
  } else if (speedMph <= 2000) {
    baseScore = 70 + ((speedMph - 1000) / 1000) * 15; // 70-85
  } else if (speedMph <= 5000) {
    baseScore = 85 + ((speedMph - 2000) / 3000) * 10; // 85-95
  } else {
    baseScore = 95 + Math.min((speedMph - 5000) / 10000 * 5, 5); // 95-100
  }

  // Reduce score if VPN is detected (location might not be accurate)
  if (isVPN) {
    baseScore *= 0.6; // 40% reduction
  }

  // Significantly reduce score if this is a known travel pattern
  if (isKnownPattern) {
    baseScore *= 0.25; // 75% reduction
  }

  // Cap at 100
  return Math.min(Math.round(baseScore), 100);
}

/**
 * Generate an impossible travel alert
 */
export function generateImpossibleTravelAlert(
  login1: LoginLocation,
  login2: LoginLocation
): ImpossibleTravelAlert | null {
  const result = isImpossibleTravel(login1, login2);

  if (!result.isImpossible) {
    return null;
  }

  const vpnCheck1 = checkVPNOrProxy(login1.ip);
  const vpnCheck2 = checkVPNOrProxy(login2.ip);
  const isVPNSuspected = vpnCheck1.isVPN || vpnCheck2.isVPN;

  const isKnown =
    login1.lat !== undefined &&
    login1.lng !== undefined &&
    login2.lat !== undefined &&
    login2.lng !== undefined
      ? isKnownTravelPattern(
          login1.userId,
          { lat: login1.lat, lng: login1.lng },
          { lat: login2.lat, lng: login2.lng }
        )
      : false;

  const riskScore = calculateRiskScore(result.speed, isVPNSuspected, isKnown);

  // Determine severity based on risk score
  let severity: 'low' | 'medium' | 'high' | 'critical';
  if (riskScore >= 80) {
    severity = 'critical';
  } else if (riskScore >= 60) {
    severity = 'high';
  } else if (riskScore >= 40) {
    severity = 'medium';
  } else {
    severity = 'low';
  }

  return {
    id: `alert_${nanoid(21)}`,
    type: 'impossible_travel',
    userId: login1.userId,
    severity,
    timestamp: new Date().toISOString(),
    details: {
      fromLocation: {
        lat: login1.lat!,
        lng: login1.lng!,
        city: login1.city,
        country: login1.country,
      },
      toLocation: {
        lat: login2.lat!,
        lng: login2.lng!,
        city: login2.city,
        country: login2.country,
      },
      calculatedSpeed: Math.round(result.speed),
      distanceMiles: Math.round(result.distance || 0),
      timeDifferenceHours: result.timeHours || 0,
      fromIP: login1.ip,
      toIP: login2.ip,
      fromTimestamp: login1.timestamp.toISOString(),
      toTimestamp: login2.timestamp.toISOString(),
    },
    riskScore,
    isVPNSuspected,
    isKnownPattern: isKnown,
  };
}

/**
 * ImpossibleTravelDetector class for comprehensive analysis
 */
export class ImpossibleTravelDetector {
  private speedThresholdMph: number;
  private userExceptions: Map<string, TravelPattern[]> = new Map();

  constructor(config: DetectorConfig = {}) {
    this.speedThresholdMph = config.speedThresholdMph || DEFAULT_SPEED_THRESHOLD_MPH;
  }

  /**
   * Analyze a pair of login events
   */
  analyzeLoginPair(login1: LoginLocation, login2: LoginLocation): TravelAnalysis {
    // Check for missing geo data
    if (
      login1.lat === undefined ||
      login1.lng === undefined ||
      login2.lat === undefined ||
      login2.lng === undefined
    ) {
      return {
        isImpossible: false,
        distance: 0,
        timeHours: 0,
        speedMph: 0,
        missingGeoData: true,
        fromLogin: login1,
        toLogin: login2,
        isVPN: false,
        isKnownPattern: false,
      };
    }

    const distance = calculateHaversineDistance(login1.lat, login1.lng, login2.lat, login2.lng);

    const timeHours = calculateTimeDifference(login1.timestamp, login2.timestamp);
    const speedMph = calculateTravelSpeed(distance, timeHours);

    const vpnCheck1 = checkVPNOrProxy(login1.ip);
    const vpnCheck2 = checkVPNOrProxy(login2.ip);
    const isVPN = vpnCheck1.isVPN || vpnCheck2.isVPN;

    // Check both global patterns and user-specific exceptions
    const isKnown =
      isKnownTravelPattern(
        login1.userId,
        { lat: login1.lat, lng: login1.lng },
        { lat: login2.lat, lng: login2.lng }
      ) ||
      this.isUserException(
        login1.userId,
        { lat: login1.lat, lng: login1.lng },
        { lat: login2.lat, lng: login2.lng }
      );

    return {
      isImpossible: speedMph > this.speedThresholdMph,
      distance,
      timeHours,
      speedMph,
      missingGeoData: false,
      fromLogin: login1,
      toLogin: login2,
      isVPN,
      isKnownPattern: isKnown,
    };
  }

  /**
   * Check if a travel pattern is a user-specific exception
   */
  private isUserException(userId: string, from: Coordinates, to: Coordinates): boolean {
    const exceptions = this.userExceptions.get(userId);
    if (!exceptions || exceptions.length === 0) {
      return false;
    }

    for (const pattern of exceptions) {
      // Check forward direction
      const fromMatchesFrom = areCoordinatesNearby(
        from.lat,
        from.lng,
        pattern.fromLocation.lat,
        pattern.fromLocation.lng,
        LOCATION_TOLERANCE_MILES
      );
      const toMatchesTo = areCoordinatesNearby(
        to.lat,
        to.lng,
        pattern.toLocation.lat,
        pattern.toLocation.lng,
        LOCATION_TOLERANCE_MILES
      );

      if (fromMatchesFrom && toMatchesTo) {
        return true;
      }

      // Check reverse direction
      const fromMatchesTo = areCoordinatesNearby(
        from.lat,
        from.lng,
        pattern.toLocation.lat,
        pattern.toLocation.lng,
        LOCATION_TOLERANCE_MILES
      );
      const toMatchesFrom = areCoordinatesNearby(
        to.lat,
        to.lng,
        pattern.fromLocation.lat,
        pattern.fromLocation.lng,
        LOCATION_TOLERANCE_MILES
      );

      if (fromMatchesTo && toMatchesFrom) {
        return true;
      }
    }

    return false;
  }

  /**
   * Detect impossible travel for a new login event
   */
  async detectImpossibleTravel(
    userId: string,
    newLogin: LoginLocation
  ): Promise<ImpossibleTravelAlert | null> {
    // In a real implementation, this would fetch the previous login from the database
    // For now, this is a placeholder that would integrate with LoginEventService
    return null;
  }

  /**
   * Analyze a sequence of logins and generate alerts for impossible travel
   */
  async analyzeLoginSequence(
    userId: string,
    logins: LoginLocation[]
  ): Promise<ImpossibleTravelAlert[]> {
    if (logins.length < 2) {
      return [];
    }

    // Sort by timestamp
    const sortedLogins = [...logins].sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );

    const alerts: ImpossibleTravelAlert[] = [];

    // Compare consecutive logins
    for (let i = 0; i < sortedLogins.length - 1; i++) {
      const login1 = sortedLogins[i];
      const login2 = sortedLogins[i + 1];

      const analysis = this.analyzeLoginPair(login1, login2);

      if (analysis.isImpossible) {
        const riskScore = this.getRiskScore(analysis);

        // Determine severity
        let severity: 'low' | 'medium' | 'high' | 'critical';
        if (riskScore >= 80) {
          severity = 'critical';
        } else if (riskScore >= 60) {
          severity = 'high';
        } else if (riskScore >= 40) {
          severity = 'medium';
        } else {
          severity = 'low';
        }

        alerts.push({
          id: `alert_${nanoid(21)}`,
          type: 'impossible_travel',
          userId,
          severity,
          timestamp: new Date().toISOString(),
          details: {
            fromLocation: {
              lat: login1.lat!,
              lng: login1.lng!,
              city: login1.city,
              country: login1.country,
            },
            toLocation: {
              lat: login2.lat!,
              lng: login2.lng!,
              city: login2.city,
              country: login2.country,
            },
            calculatedSpeed: Math.round(analysis.speedMph),
            distanceMiles: Math.round(analysis.distance),
            timeDifferenceHours: analysis.timeHours,
            fromIP: login1.ip,
            toIP: login2.ip,
            fromTimestamp: login1.timestamp.toISOString(),
            toTimestamp: login2.timestamp.toISOString(),
          },
          riskScore,
          isVPNSuspected: analysis.isVPN,
          isKnownPattern: analysis.isKnownPattern,
        });
      }
    }

    return alerts;
  }

  /**
   * Add a travel exception for a specific user
   */
  addTravelException(userId: string, pattern: TravelPattern): void {
    const existing = this.userExceptions.get(userId) || [];
    existing.push(pattern);
    this.userExceptions.set(userId, existing);

    // Also add to global patterns
    addKnownTravelPattern(pattern);
  }

  /**
   * Calculate risk score for a travel analysis
   */
  getRiskScore(analysis: TravelAnalysis): number {
    return calculateRiskScore(analysis.speedMph, analysis.isVPN, analysis.isKnownPattern);
  }

  /**
   * Check if a calculated speed is impossible
   */
  isImpossible(speedMph: number, threshold?: number): boolean {
    return speedMph > (threshold || this.speedThresholdMph);
  }
}

/**
 * Create a new ImpossibleTravelDetector instance
 */
export function createImpossibleTravelDetector(
  config?: DetectorConfig
): ImpossibleTravelDetector {
  return new ImpossibleTravelDetector(config);
}

/**
 * Default detector instance
 */
export const defaultImpossibleTravelDetector = createImpossibleTravelDetector();
