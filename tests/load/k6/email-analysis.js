/**
 * K6 Load Test: Email Analysis Endpoint
 *
 * Tests the /api/analyze endpoint which is the core email scanning API
 * Run: k6 run tests/load/k6/email-analysis.js
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';

// Custom metrics
const analysisSuccessRate = new Rate('analysis_success');
const analysisLatency = new Trend('analysis_latency');
const quickCheckLatency = new Trend('quickcheck_latency');
const errorCounter = new Counter('analysis_errors');
const throughput = new Gauge('current_throughput');

// Test configuration - conservative for email analysis which is CPU-intensive
export const options = {
  scenarios: {
    // Quick check tests - higher volume
    quick_checks: {
      executor: 'constant-arrival-rate',
      rate: 50,              // 50 RPS for quick checks
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 30,
      exec: 'quickCheckTest',
    },
    // Full analysis - lower volume, longer running
    full_analysis: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '30s', target: 5 },
        { duration: '2m', target: 10 },
        { duration: '30s', target: 5 },
        { duration: '30s', target: 0 },
      ],
      exec: 'fullAnalysisTest',
      startTime: '30s',
    },
    // Stress test - find breaking point
    stress: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 100,
      stages: [
        { duration: '30s', target: 30 },
        { duration: '1m', target: 50 },
        { duration: '30s', target: 75 },
        { duration: '30s', target: 100 },
        { duration: '30s', target: 0 },
      ],
      exec: 'quickCheckTest',
      startTime: '4m',
    },
  },
  thresholds: {
    'analysis_latency': ['p(95)<3000', 'p(99)<5000'],  // Full analysis
    'quickcheck_latency': ['p(95)<500', 'p(99)<1000'], // Quick check
    'analysis_success': ['rate>0.95'],
    'http_req_failed': ['rate<0.05'],
  },
};

// Environment configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const AUTH_TOKEN = __ENV.AUTH_TOKEN || '';

// Sample email payloads
const sampleEmails = [
  // Clean email
  {
    parsed: {
      messageId: 'test-clean-' + Date.now(),
      from: { name: 'John Doe', email: 'john@example.com' },
      to: [{ name: 'Jane Smith', email: 'jane@company.com' }],
      subject: 'Q4 Report Review',
      date: new Date().toISOString(),
      body: {
        plain: 'Hi Jane,\n\nPlease review the attached Q4 report when you have a moment.\n\nBest,\nJohn',
        html: '<p>Hi Jane,</p><p>Please review the attached Q4 report when you have a moment.</p><p>Best,<br>John</p>',
      },
      headers: {
        received: ['from mail.example.com (192.168.1.1)'],
      },
    },
    quickCheckOnly: false,
  },
  // Phishing-like email
  {
    parsed: {
      messageId: 'test-phish-' + Date.now(),
      from: { name: 'Security Team', email: 'security@company-support.xyz' },
      to: [{ name: 'Employee', email: 'employee@company.com' }],
      subject: 'URGENT: Password Reset Required',
      date: new Date().toISOString(),
      body: {
        plain: 'Your password will expire in 24 hours. Click here to reset: http://fake-login.xyz/reset',
        html: '<p>Your password will expire in 24 hours.</p><a href="http://fake-login.xyz/reset">Click here to reset</a>',
      },
      headers: {
        received: ['from unknown.server.xyz (10.0.0.1)'],
      },
    },
    quickCheckOnly: false,
  },
  // BEC-like email
  {
    parsed: {
      messageId: 'test-bec-' + Date.now(),
      from: { name: 'CEO Name', email: 'ceo@company-exec.com' },
      to: [{ name: 'Finance', email: 'finance@company.com' }],
      subject: 'Urgent Wire Transfer',
      date: new Date().toISOString(),
      body: {
        plain: 'I need you to process an urgent wire transfer of $50,000 to this account. Please do this immediately and keep it confidential.',
        html: '<p>I need you to process an urgent wire transfer of $50,000 to this account. Please do this immediately and keep it confidential.</p>',
      },
      headers: {
        received: ['from mail.external.com (203.0.113.50)'],
      },
    },
    quickCheckOnly: false,
  },
];

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

// Get a random email payload with unique ID
function getRandomEmail(quickOnly = false) {
  const template = sampleEmails[Math.floor(Math.random() * sampleEmails.length)];
  return {
    ...template,
    parsed: {
      ...template.parsed,
      messageId: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    },
    quickCheckOnly: quickOnly,
  };
}

// Quick check test - fast, high-volume
export function quickCheckTest() {
  const headers = getHeaders();
  const email = getRandomEmail(true);

  group('Quick Check Analysis', () => {
    const startTime = Date.now();

    const res = http.post(
      `${BASE_URL}/api/analyze`,
      JSON.stringify(email),
      { headers, timeout: '5s' }
    );

    const latency = Date.now() - startTime;
    quickCheckLatency.add(latency);

    const success = check(res, {
      'quickcheck status 200 or 401': (r) => r.status === 200 || r.status === 401,
      'quickcheck response is JSON': (r) => {
        const ct = r.headers['Content-Type'];
        return ct && ct.includes('application/json');
      },
      'quickcheck latency under 500ms': () => latency < 500,
      'quickcheck has verdict': (r) => {
        if (r.status === 401) return true; // Skip auth failures
        try {
          const body = JSON.parse(r.body);
          return body.verdict !== undefined || body.needsFullAnalysis !== undefined;
        } catch {
          return false;
        }
      },
    });

    analysisSuccessRate.add(success);
    if (!success) {
      errorCounter.add(1);
      console.log(`Quick check failed: ${res.status} - ${res.body?.substring(0, 200)}`);
    }
  });

  sleep(Math.random() * 0.5);
}

// Full analysis test - slower, lower volume
export function fullAnalysisTest() {
  const headers = getHeaders();
  const email = getRandomEmail(false);

  group('Full Email Analysis', () => {
    const startTime = Date.now();

    const res = http.post(
      `${BASE_URL}/api/analyze`,
      JSON.stringify(email),
      { headers, timeout: '30s' }
    );

    const latency = Date.now() - startTime;
    analysisLatency.add(latency);

    const success = check(res, {
      'analysis status 200 or 401': (r) => r.status === 200 || r.status === 401,
      'analysis response is JSON': (r) => {
        const ct = r.headers['Content-Type'];
        return ct && ct.includes('application/json');
      },
      'analysis has complete response': (r) => {
        if (r.status === 401) return true;
        try {
          const body = JSON.parse(r.body);
          return body.verdict && body.score !== undefined;
        } catch {
          return false;
        }
      },
      'analysis latency under 3s': () => latency < 3000,
    });

    analysisSuccessRate.add(success);
    if (!success) {
      errorCounter.add(1);
      console.log(`Full analysis failed: ${res.status} - ${res.body?.substring(0, 200)}`);
    }
  });

  sleep(1 + Math.random() * 2);
}

// Default test (mixed workload)
export default function () {
  if (Math.random() < 0.7) {
    quickCheckTest();
  } else {
    fullAnalysisTest();
  }
}

export function setup() {
  console.log(`Starting email analysis load tests against ${BASE_URL}`);

  // Verify analyze endpoint is available
  const healthRes = http.get(`${BASE_URL}/api/analyze`, {
    headers: { 'Accept': 'application/json' },
  });

  console.log(`Analyze endpoint check: ${healthRes.status}`);

  return { startTime: Date.now() };
}

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Email analysis tests completed in ${duration.toFixed(1)}s`);
}
