/**
 * K6 Load Test: Health Endpoint
 *
 * Tests the /api/health endpoint under load
 * Run: k6 run tests/load/k6/health.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const healthyRate = new Rate('healthy_responses');
const latencyTrend = new Trend('health_latency');
const errorCounter = new Counter('errors');

// Test configuration
export const options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up to 10 users
    { duration: '1m', target: 50 },    // Ramp up to 50 users
    { duration: '2m', target: 50 },    // Stay at 50 users
    { duration: '1m', target: 100 },   // Spike to 100 users
    { duration: '30s', target: 100 },  // Hold at 100
    { duration: '30s', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],  // 95% under 500ms
    http_req_failed: ['rate<0.01'],                   // Less than 1% failures
    healthy_responses: ['rate>0.99'],                 // 99% healthy
  },
};

// Environment configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export default function () {
  const startTime = Date.now();

  const res = http.get(`${BASE_URL}/api/health`, {
    headers: {
      'Accept': 'application/json',
    },
    timeout: '10s',
  });

  const latency = Date.now() - startTime;
  latencyTrend.add(latency);

  // Check response
  const isHealthy = check(res, {
    'status is 200': (r) => r.status === 200,
    'response is JSON': (r) => r.headers['Content-Type']?.includes('application/json'),
    'status is healthy': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.status === 'healthy' || body.status === 'degraded';
      } catch {
        return false;
      }
    },
    'latency under 500ms': () => latency < 500,
  });

  healthyRate.add(isHealthy);

  if (!isHealthy) {
    errorCounter.add(1);
    console.log(`Health check failed: ${res.status} - ${res.body}`);
  }

  // Small random sleep to simulate real traffic patterns
  sleep(Math.random() * 0.5);
}

// Lifecycle hooks
export function setup() {
  console.log(`Starting health endpoint load test against ${BASE_URL}`);

  // Verify endpoint is reachable
  const res = http.get(`${BASE_URL}/api/health`);
  if (res.status !== 200) {
    throw new Error(`Health endpoint not reachable: ${res.status}`);
  }

  return { startTime: Date.now() };
}

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Health endpoint test completed in ${duration}s`);
}
