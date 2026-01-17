/**
 * Distance Calculator Module
 *
 * Provides accurate distance calculations between geographic coordinates
 * using the Haversine formula. Essential for impossible travel detection.
 */

/**
 * Earth's radius in miles (mean radius)
 */
const EARTH_RADIUS_MILES = 3958.8;

/**
 * Convert degrees to radians
 */
function toRadians(degrees: number): number {
  return degrees * (Math.PI / 180);
}

/**
 * Calculate the distance between two geographic points using the Haversine formula
 *
 * The Haversine formula determines the great-circle distance between two points
 * on a sphere given their latitudes and longitudes. This is the shortest distance
 * over the earth's surface.
 *
 * @param lat1 - Latitude of the first point in degrees
 * @param lng1 - Longitude of the first point in degrees
 * @param lat2 - Latitude of the second point in degrees
 * @param lng2 - Longitude of the second point in degrees
 * @returns Distance in miles
 */
export function calculateHaversineDistance(
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number
): number {
  // Return 0 for identical coordinates
  if (lat1 === lat2 && lng1 === lng2) {
    return 0;
  }

  // Convert to radians
  const phi1 = toRadians(lat1);
  const phi2 = toRadians(lat2);
  const deltaPhi = toRadians(lat2 - lat1);
  const deltaLambda = toRadians(lng2 - lng1);

  // Haversine formula
  const a =
    Math.sin(deltaPhi / 2) * Math.sin(deltaPhi / 2) +
    Math.cos(phi1) * Math.cos(phi2) * Math.sin(deltaLambda / 2) * Math.sin(deltaLambda / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  // Distance in miles
  const distance = EARTH_RADIUS_MILES * c;

  return distance;
}

/**
 * Calculate distance in kilometers
 *
 * @param lat1 - Latitude of the first point in degrees
 * @param lng1 - Longitude of the first point in degrees
 * @param lat2 - Latitude of the second point in degrees
 * @param lng2 - Longitude of the second point in degrees
 * @returns Distance in kilometers
 */
export function calculateHaversineDistanceKm(
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number
): number {
  const distanceMiles = calculateHaversineDistance(lat1, lng1, lat2, lng2);
  return distanceMiles * 1.60934; // Convert miles to km
}

/**
 * Check if two coordinates are within a specified tolerance (in miles)
 *
 * @param lat1 - Latitude of the first point
 * @param lng1 - Longitude of the first point
 * @param lat2 - Latitude of the second point
 * @param lng2 - Longitude of the second point
 * @param toleranceMiles - Maximum distance to consider as "same location"
 * @returns True if the coordinates are within the tolerance
 */
export function areCoordinatesNearby(
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number,
  toleranceMiles: number = 1
): boolean {
  const distance = calculateHaversineDistance(lat1, lng1, lat2, lng2);
  return distance <= toleranceMiles;
}
