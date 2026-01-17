/**
 * Email Authentication Module
 *
 * Provides SPF, DKIM, and DMARC validation for email security
 */

export * from './types';
export * from './dns-resolver';
export * from './spf';
export * from './dkim';
export * from './dmarc';

import { SPFValidator } from './spf';
import { DKIMValidator } from './dkim';
import { DMARCEvaluator } from './dmarc';
import { CachingDNSResolver, MemoryDNSCache, MockDNSResolver } from './dns-resolver';
import type {
  DNSResolver,
  EmailAuthContext,
  SPFValidationResult,
  DKIMValidationResult,
  DMARCEvaluationResult,
} from './types';

export interface EmailAuthResult {
  spf: SPFValidationResult;
  dkim: DKIMValidationResult[];
  dmarc: DMARCEvaluationResult;
  summary: {
    authenticated: boolean;
    confidence: number;
    warnings: string[];
  };
}

/**
 * Complete email authentication suite
 */
export class EmailAuthenticator {
  private spfValidator: SPFValidator;
  private dkimValidator: DKIMValidator;
  private dmarcEvaluator: DMARCEvaluator;

  constructor(resolver?: DNSResolver) {
    const dnsResolver = resolver || new MockDNSResolver();

    this.spfValidator = new SPFValidator(dnsResolver);
    this.dkimValidator = new DKIMValidator(dnsResolver);
    this.dmarcEvaluator = new DMARCEvaluator(dnsResolver);
  }

  /**
   * Perform complete email authentication
   */
  async authenticate(context: EmailAuthContext): Promise<EmailAuthResult> {
    const warnings: string[] = [];

    // Extract domain from mailFrom
    const mailFromDomain = context.mailFrom.split('@').pop() || '';

    // 1. SPF Validation
    const spfResult = await this.spfValidator.validate(
      context.senderIP,
      context.mailFrom,
      mailFromDomain
    );

    // 2. DKIM Validation
    const dkimResults: DKIMValidationResult[] = [];

    if (context.dkimSignatures && context.rawHeaders && context.rawBody !== undefined) {
      for (const sig of context.dkimSignatures) {
        const result = await this.dkimValidator.verify(
          context.rawHeaders,
          context.rawBody,
          sig
        );
        dkimResults.push(result);
      }
    }

    // 3. DMARC Evaluation
    const dmarcResult = await this.dmarcEvaluator.evaluate({
      headerFrom: context.headerFrom,
      mailFrom: context.mailFrom,
      spfResult: spfResult.result,
      dkimResults,
    });

    // Build summary
    const authenticated = dmarcResult.result === 'pass';
    let confidence = 0;

    if (spfResult.result === 'pass') {
      confidence += 30;
      if (dmarcResult.spfAlignment) confidence += 20;
    }

    if (dkimResults.some(r => r.result === 'pass')) {
      confidence += 30;
      if (dmarcResult.dkimAlignment) confidence += 20;
    }

    // Add warnings
    if (spfResult.result === 'none') {
      warnings.push('No SPF record found for sender domain');
    }

    if (spfResult.result === 'softfail') {
      warnings.push('SPF softfail: sender is not explicitly authorized');
    }

    if (dkimResults.length === 0) {
      warnings.push('No DKIM signatures found');
    }

    if (dmarcResult.result === 'none') {
      warnings.push('No DMARC policy published for sender domain');
    }

    if (dmarcResult.result === 'fail') {
      warnings.push(`DMARC check failed - policy recommends: ${dmarcResult.appliedPolicy}`);
    }

    return {
      spf: spfResult,
      dkim: dkimResults,
      dmarc: dmarcResult,
      summary: {
        authenticated,
        confidence,
        warnings,
      },
    };
  }

  /**
   * Get the SPF validator for direct access
   */
  get spf(): SPFValidator {
    return this.spfValidator;
  }

  /**
   * Get the DKIM validator for direct access
   */
  get dkim(): DKIMValidator {
    return this.dkimValidator;
  }

  /**
   * Get the DMARC evaluator for direct access
   */
  get dmarc(): DMARCEvaluator {
    return this.dmarcEvaluator;
  }
}

/**
 * Create an email authenticator with caching DNS resolver
 */
export function createEmailAuthenticator(): EmailAuthenticator {
  // In a real application, you would create a proper DNS resolver
  // For now, we use a mock that can be configured
  const mockResolver = new MockDNSResolver();
  return new EmailAuthenticator(mockResolver);
}

/**
 * Create a mock email authenticator for testing
 */
export function createMockEmailAuthenticator(): {
  authenticator: EmailAuthenticator;
  dns: MockDNSResolver;
} {
  const dns = new MockDNSResolver();
  const authenticator = new EmailAuthenticator(dns);
  return { authenticator, dns };
}
