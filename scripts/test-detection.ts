#!/usr/bin/env npx tsx

/**
 * Test script for the detection engine
 * Run with: npx tsx scripts/test-detection.ts
 */

import { parseEmail } from '../lib/detection/parser';
import { runDeterministicAnalysis } from '../lib/detection/deterministic';

// Sample phishing email for testing
const PHISHING_EMAIL = `From: "PayPal Support" <security@paypa1-verify.com>
To: victim@example.com
Subject: URGENT: Your account has been suspended - Verify immediately!
Date: Mon, 1 Jan 2024 10:00:00 -0500
Message-ID: <test123@example.com>
Content-Type: text/plain

Dear Valued Customer,

Your PayPal account has been temporarily suspended due to suspicious activity.

URGENT: You must verify your account immediately to avoid permanent closure.

Click here to verify your account: http://192.168.1.1/paypal-verify

If you do not verify within 24 hours, your account will be permanently deleted and all funds will be lost.

Please have your password and credit card information ready for verification.

Best regards,
PayPal Security Team
`;

// Sample legitimate email for testing
const LEGITIMATE_EMAIL = `From: "John Smith" <john.smith@acme-corp.com>
To: colleague@example.com
Subject: Re: Q4 Budget Review Meeting
Date: Mon, 1 Jan 2024 09:00:00 -0500
Message-ID: <meeting456@acme-corp.com>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

Hi,

Thanks for sending over the Q4 budget documents. I've reviewed them and have a few questions.

Can we schedule a call this week to discuss? I'm available Tuesday or Wednesday afternoon.

Looking forward to connecting.

Best,
John
`;

async function main() {
  console.log('=== Swordfish Detection Engine Test ===\n');

  // Test 1: Parse and analyze phishing email
  console.log('--- Test 1: Phishing Email ---');
  const phishingParsed = parseEmail(PHISHING_EMAIL);
  console.log(`From: ${phishingParsed.from.displayName} <${phishingParsed.from.address}>`);
  console.log(`Domain: ${phishingParsed.from.domain}`);
  console.log(`Subject: ${phishingParsed.subject}`);

  const phishingResult = await runDeterministicAnalysis(phishingParsed);
  console.log(`\nScore: ${phishingResult.score}/100`);
  console.log(`Confidence: ${(phishingResult.confidence * 100).toFixed(0)}%`);
  console.log(`Processing time: ${phishingResult.processingTimeMs.toFixed(2)}ms`);
  console.log('\nSignals detected:');
  for (const signal of phishingResult.signals) {
    const icon = signal.severity === 'critical' ? '🚨' : signal.severity === 'warning' ? '⚠️' : 'ℹ️';
    console.log(`  ${icon} [${signal.type}] ${signal.detail} (score: ${signal.score})`);
  }

  // Test 2: Parse and analyze legitimate email
  console.log('\n--- Test 2: Legitimate Email ---');
  const legitimateParsed = parseEmail(LEGITIMATE_EMAIL);
  console.log(`From: ${legitimateParsed.from.displayName} <${legitimateParsed.from.address}>`);
  console.log(`Domain: ${legitimateParsed.from.domain}`);
  console.log(`Subject: ${legitimateParsed.subject}`);

  const legitimateResult = await runDeterministicAnalysis(legitimateParsed);
  console.log(`\nScore: ${legitimateResult.score}/100`);
  console.log(`Confidence: ${(legitimateResult.confidence * 100).toFixed(0)}%`);
  console.log(`Processing time: ${legitimateResult.processingTimeMs.toFixed(2)}ms`);
  console.log('\nSignals detected:');
  if (legitimateResult.signals.length === 0) {
    console.log('  ✅ No suspicious signals detected');
  } else {
    for (const signal of legitimateResult.signals) {
      const icon = signal.severity === 'critical' ? '🚨' : signal.severity === 'warning' ? '⚠️' : 'ℹ️';
      console.log(`  ${icon} [${signal.type}] ${signal.detail} (score: ${signal.score})`);
    }
  }

  // Summary
  console.log('\n=== Summary ===');
  console.log(`Phishing email score: ${phishingResult.score} (expected: high)`);
  console.log(`Legitimate email score: ${legitimateResult.score} (expected: low)`);

  const phishingDetected = phishingResult.score >= 50;
  const legitimatePassed = legitimateResult.score < 30;

  console.log(`\nPhishing correctly flagged: ${phishingDetected ? '✅ YES' : '❌ NO'}`);
  console.log(`Legitimate correctly passed: ${legitimatePassed ? '✅ YES' : '❌ NO'}`);
}

main().catch(console.error);
