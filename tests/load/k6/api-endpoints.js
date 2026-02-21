/**
 * K6 Load Test: Core API Endpoints
 *
 * Tests multiple API endpoints under realistic load patterns
 * Run: k6 run tests/load/k6/api-endpoints.js
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const successRate = new Rate('success_rate');
const threatsLatency = new Trend('threats_latency');
const statsLatency = new Trend('stats_latency');
const analyticsLatency = new Trend('analytics_latency');
const errorCounter = new Counter('api_errors');

// Test configuration
export const options = {
  scenarios: {
    // Baseline load
    baseline: {
      executor: 'constant-vus',
      vus: 10,
      duration: '2m',
      gracefulStop: '10s',
    },
    // Spike test
    spike: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 20 },
        { duration: '1m', target: 50 },
        { duration: '30s', target: 100 },
        { duration: '30s', target: 50 },
        { duration: '30s', target: 0 },
      ],
      startTime: '2m30s', // Start after baseline
    },
    // Sustained load
    sustained: {
      executor: 'constant-arrival-rate',
      rate: 100,           // 100 RPS
      timeUnit: '1s',
      duration: '3m',
      preAllocatedVUs: 50,
      startTime: '6m',     // Start after spike
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<1000', 'p(99)<2000'],
    http_req_failed: ['rate<0.05'],
    success_rate: ['rate>0.95'],
    threats_latency: ['p(95)<800'],
    stats_latency: ['p(95)<500'],
  },
};

// Environment configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const AUTH_TOKEN = __ENV.AUTH_TOKEN || '';

// Common headers
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

export default function () {
  const headers = getHeaders();

  // Randomly choose an endpoint to test (weighted by typical usage)
  const rand = Math.random();

  if (rand < 0.4) {
    testThreatsEndpoint(headers);
  } else if (rand < 0.7) {
    testStatsEndpoint(headers);
  } else if (rand < 0.9) {
    testAnalyticsEndpoint(headers);
  } else {
    testNotificationsEndpoint(headers);
  }

  sleep(Math.random() * 2);
}

function testThreatsEndpoint(headers) {
  group('Threats API', () => {
    const startTime = Date.now();

    const res = http.get(`${BASE_URL}/api/threats?limit=20&status=active`, {
      headers,
      timeout: '15s',
    });

    const latency = Date.now() - startTime;
    threatsLatency.add(latency);

    const success = check(res, {
      'threats status 200 or 401': (r) => r.status === 200 || r.status === 401,
      'threats response is JSON': (r) => {
        const ct = r.headers['Content-Type'];
        return ct && ct.includes('application/json');
      },
      'threats latency OK': () => latency < 1000,
    });

    successRate.add(success);
    if (!success) errorCounter.add(1);
  });
}

function testStatsEndpoint(headers) {
  group('Dashboard Stats API', () => {
    const startTime = Date.now();

    const res = http.get(`${BASE_URL}/api/stats`, {
      headers,
      timeout: '10s',
    });

    const latency = Date.now() - startTime;
    statsLatency.add(latency);

    const success = check(res, {
      'stats status 200 or 401': (r) => r.status === 200 || r.status === 401,
      'stats response is JSON': (r) => {
        const ct = r.headers['Content-Type'];
        return ct && ct.includes('application/json');
      },
      'stats latency OK': () => latency < 500,
    });

    successRate.add(success);
    if (!success) errorCounter.add(1);
  });
}

function testAnalyticsEndpoint(headers) {
  group('Analytics API', () => {
    const startTime = Date.now();

    const res = http.get(`${BASE_URL}/api/analytics?period=7d`, {
      headers,
      timeout: '15s',
    });

    const latency = Date.now() - startTime;
    analyticsLatency.add(latency);

    const success = check(res, {
      'analytics status 200 or 401': (r) => r.status === 200 || r.status === 401,
      'analytics response is JSON': (r) => {
        const ct = r.headers['Content-Type'];
        return ct && ct.includes('application/json');
      },
      'analytics latency OK': () => latency < 1500,
    });

    successRate.add(success);
    if (!success) errorCounter.add(1);
  });
}

function testNotificationsEndpoint(headers) {
  group('Notifications API', () => {
    const startTime = Date.now();

    const res = http.get(`${BASE_URL}/api/notifications?limit=10`, {
      headers,
      timeout: '10s',
    });

    const latency = Date.now() - startTime;

    const success = check(res, {
      'notifications status 200 or 401': (r) => r.status === 200 || r.status === 401,
      'notifications response is JSON': (r) => {
        const ct = r.headers['Content-Type'];
        return ct && ct.includes('application/json');
      },
      'notifications latency OK': () => latency < 500,
    });

    successRate.add(success);
    if (!success) errorCounter.add(1);
  });
}

export function setup() {
  console.log(`Starting API endpoint load tests against ${BASE_URL}`);
  console.log(`Auth token configured: ${AUTH_TOKEN ? 'Yes' : 'No'}`);

  // Health check
  const healthRes = http.get(`${BASE_URL}/api/health`);
  if (healthRes.status !== 200) {
    console.warn(`Warning: Health check returned ${healthRes.status}`);
  }

  return { startTime: Date.now() };
}

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`API endpoint tests completed in ${duration.toFixed(1)}s`);
}
