/**
 * K6 Soak Test: Extended Duration Stability Test
 *
 * Tests system stability over extended periods to detect:
 * - Memory leaks
 * - Connection pool exhaustion
 * - Database connection issues
 * - Gradual performance degradation
 *
 * Run: k6 run --duration 30m tests/load/k6/soak-test.js
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';

// Custom metrics
const successRate = new Rate('success_rate');
const healthLatency = new Trend('health_latency');
const apiLatency = new Trend('api_latency');
const errorCounter = new Counter('errors');
const memoryGauge = new Gauge('reported_memory');

// Soak test configuration - moderate sustained load
export const options = {
  scenarios: {
    soak: {
      executor: 'constant-arrival-rate',
      rate: 20,              // 20 RPS sustained
      timeUnit: '1s',
      duration: '30m',       // 30 minute soak test
      preAllocatedVUs: 30,
      maxVUs: 50,
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<1500', 'p(99)<3000'],
    http_req_failed: ['rate<0.02'],    // Less than 2% failure rate
    success_rate: ['rate>0.98'],        // 98% success
  },
};

// Environment configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const AUTH_TOKEN = __ENV.AUTH_TOKEN || '';

// Headers
function getHeaders() {
  const headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
  };
  if (AUTH_TOKEN) {
    headers['Authorization'] = `Bearer ${AUTH_TOKEN}`;
  }
  return headers;
}

// Track iteration count for periodic detailed checks
let iterationCount = 0;

export default function () {
  iterationCount++;
  const headers = getHeaders();

  // Randomly distribute across endpoints
  const rand = Math.random();

  if (rand < 0.3) {
    // Health checks - 30%
    checkHealth(headers);
  } else if (rand < 0.6) {
    // API reads - 30%
    checkApi(headers);
  } else if (rand < 0.9) {
    // Dashboard/Stats - 30%
    checkStats(headers);
  } else {
    // Detailed health - 10%
    detailedHealthCheck(headers);
  }

  sleep(Math.random() * 3);
}

function checkHealth(headers) {
  group('Health Check', () => {
    const startTime = Date.now();

    const res = http.get(`${BASE_URL}/api/health`, { headers, timeout: '10s' });

    const latency = Date.now() - startTime;
    healthLatency.add(latency);

    const success = check(res, {
      'health status 200': (r) => r.status === 200,
      'health is healthy': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.status === 'healthy' || body.status === 'degraded';
        } catch {
          return false;
        }
      },
    });

    successRate.add(success);
    if (!success) errorCounter.add(1);

    // Extract memory info if available
    try {
      const body = JSON.parse(res.body);
      const memCheck = body.checks?.find(c => c.name === 'memory');
      if (memCheck && memCheck.message) {
        const match = memCheck.message.match(/Heap:\s*(\d+)MB/);
        if (match) {
          memoryGauge.add(parseInt(match[1], 10));
        }
      }
    } catch {
      // Ignore parsing errors
    }
  });
}

function checkApi(headers) {
  group('API Read', () => {
    const startTime = Date.now();

    // Randomly check threats or notifications
    const endpoint = Math.random() < 0.5
      ? '/api/threats?limit=10'
      : '/api/notifications?limit=10';

    const res = http.get(`${BASE_URL}${endpoint}`, { headers, timeout: '15s' });

    const latency = Date.now() - startTime;
    apiLatency.add(latency);

    const success = check(res, {
      'api status 200 or 401': (r) => r.status === 200 || r.status === 401,
      'api response is JSON': (r) => {
        const ct = r.headers['Content-Type'];
        return ct && ct.includes('application/json');
      },
    });

    successRate.add(success);
    if (!success) errorCounter.add(1);
  });
}

function checkStats(headers) {
  group('Stats Check', () => {
    const startTime = Date.now();

    const res = http.get(`${BASE_URL}/api/stats`, { headers, timeout: '10s' });

    const latency = Date.now() - startTime;
    apiLatency.add(latency);

    const success = check(res, {
      'stats status 200 or 401': (r) => r.status === 200 || r.status === 401,
    });

    successRate.add(success);
    if (!success) errorCounter.add(1);
  });
}

function detailedHealthCheck(headers) {
  group('Detailed Health', () => {
    // Check all critical endpoints in sequence
    const endpoints = [
      { name: 'health', url: '/api/health' },
      { name: 'analyze', url: '/api/analyze' },
      { name: 'metrics', url: '/api/metrics' },
    ];

    for (const ep of endpoints) {
      const res = http.get(`${BASE_URL}${ep.url}`, { headers, timeout: '10s' });

      const success = check(res, {
        [`${ep.name} available`]: (r) => r.status === 200 || r.status === 401,
      });

      if (!success) {
        console.log(`[Soak] ${ep.name} check failed: ${res.status}`);
        errorCounter.add(1);
      }
    }

    // Log periodic status
    if (iterationCount % 100 === 0) {
      console.log(`[Soak] Completed ${iterationCount} iterations`);
    }
  });
}

export function setup() {
  console.log(`Starting soak test against ${BASE_URL}`);
  console.log('Duration: 30 minutes');
  console.log('Target rate: 20 RPS');

  // Initial health verification
  const res = http.get(`${BASE_URL}/api/health`);
  console.log(`Initial health check: ${res.status}`);

  return {
    startTime: Date.now(),
    initialHealth: res.status,
  };
}

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000 / 60;
  console.log(`Soak test completed after ${duration.toFixed(1)} minutes`);
  console.log(`Total iterations: ~${iterationCount}`);

  // Final health check
  const res = http.get(`${BASE_URL}/api/health`);
  console.log(`Final health check: ${res.status}`);

  if (data.initialHealth === 200 && res.status !== 200) {
    console.warn('WARNING: System health degraded during soak test');
  }
}
