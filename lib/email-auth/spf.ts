/**
 * SPF (Sender Policy Framework) Validator
 *
 * Validates sender IP addresses against SPF records as defined in RFC 7208
 */

import type {
  DNSResolver,
  SPFResult,
  SPFRecord,
  SPFMechanism,
  SPFValidationResult,
} from './types';

const MAX_DNS_LOOKUPS = 10;

export class SPFValidator {
  private resolver: DNSResolver;
  private lookupCount: number = 0;

  constructor(resolver: DNSResolver) {
    this.resolver = resolver;
  }

  /**
   * Parse an SPF record string into structured format
   */
  parseRecord(record: string): SPFRecord {
    const trimmed = record.trim();

    // Check version
    if (!trimmed.startsWith('v=spf1')) {
      throw new Error('Invalid SPF version: record must start with v=spf1');
    }

    const mechanisms: SPFMechanism[] = [];
    let redirect: string | undefined;
    let exp: string | undefined;

    // Split by whitespace
    const terms = trimmed.split(/\s+/).slice(1); // Skip v=spf1

    for (const term of terms) {
      // Handle modifiers
      if (term.startsWith('redirect=')) {
        redirect = term.substring(9);
        continue;
      }

      if (term.startsWith('exp=')) {
        exp = term.substring(4);
        continue;
      }

      // Parse mechanism
      const mechanism = this.parseMechanism(term);
      if (mechanism) {
        mechanisms.push(mechanism);
      } else {
        // Unknown/invalid mechanism - throw permerror
        throw new Error(`Invalid SPF mechanism: ${term}`);
      }
    }

    return {
      version: 'spf1',
      mechanisms,
      redirect,
      exp,
      raw: record,
    };
  }

  /**
   * Parse a single SPF mechanism
   */
  private parseMechanism(term: string): SPFMechanism | null {
    // Determine qualifier (default is '+')
    let qualifier: '+' | '-' | '~' | '?' = '+';
    let rest = term;

    if (['+', '-', '~', '?'].includes(term[0])) {
      qualifier = term[0] as '+' | '-' | '~' | '?';
      rest = term.substring(1);
    }

    // Parse mechanism type and value
    const colonIndex = rest.indexOf(':');
    const slashIndex = rest.indexOf('/');

    let type: string;
    let value: string | undefined;
    let cidr: number | undefined;

    if (colonIndex > 0) {
      type = rest.substring(0, colonIndex).toLowerCase();
      const afterColon = rest.substring(colonIndex + 1);

      if (slashIndex > colonIndex) {
        const cidrIndex = afterColon.indexOf('/');
        value = afterColon.substring(0, cidrIndex > 0 ? cidrIndex : undefined);
        if (cidrIndex > 0) {
          cidr = parseInt(afterColon.substring(cidrIndex + 1), 10);
        }
      } else {
        value = afterColon;
      }
    } else if (slashIndex > 0) {
      type = rest.substring(0, slashIndex).toLowerCase();
      cidr = parseInt(rest.substring(slashIndex + 1), 10);
    } else {
      type = rest.toLowerCase();
    }

    // Validate mechanism type
    const validTypes = ['all', 'ip4', 'ip6', 'a', 'mx', 'ptr', 'exists', 'include'];
    if (!validTypes.includes(type)) {
      return null; // Unknown mechanism
    }

    return {
      type: type as SPFMechanism['type'],
      qualifier,
      value,
      cidr,
    };
  }

  /**
   * Validate an IP address against a domain's SPF record
   */
  async validate(
    senderIP: string,
    sender: string,
    domain: string
  ): Promise<SPFValidationResult> {
    this.lookupCount = 0;

    try {
      return await this.checkDomain(senderIP, domain);
    } catch (error) {
      if (error instanceof Error) {
        if (error.message.includes('DNS lookup limit')) {
          return {
            result: 'permerror',
            domain,
            senderIP,
            explanation: error.message,
            lookupCount: this.lookupCount,
          };
        }

        if (error.message.includes('timeout') || error.message.includes('SERVFAIL')) {
          return {
            result: 'temperror',
            domain,
            senderIP,
            explanation: error.message,
            lookupCount: this.lookupCount,
          };
        }
      }

      return {
        result: 'temperror',
        domain,
        senderIP,
        explanation: String(error),
        lookupCount: this.lookupCount,
      };
    }
  }

  /**
   * Check a domain's SPF record against the sender IP
   */
  private async checkDomain(
    senderIP: string,
    domain: string,
    isInclude: boolean = false
  ): Promise<SPFValidationResult> {
    // Get TXT records - this counts as a lookup for includes
    // Note: The initial domain lookup is free, but includes count
    const txtRecords = await this.resolver.resolveTxt(domain);

    // Filter SPF records
    const spfRecords = txtRecords.filter(r => r.startsWith('v=spf1'));

    if (spfRecords.length === 0) {
      return {
        result: 'none',
        domain,
        senderIP,
        lookupCount: this.lookupCount,
      };
    }

    if (spfRecords.length > 1) {
      return {
        result: 'permerror',
        domain,
        senderIP,
        explanation: 'Multiple SPF records found',
        lookupCount: this.lookupCount,
      };
    }

    // Parse the SPF record
    let parsed: SPFRecord;
    try {
      parsed = this.parseRecord(spfRecords[0]);
    } catch (error) {
      return {
        result: 'permerror',
        domain,
        senderIP,
        explanation: String(error),
        lookupCount: this.lookupCount,
      };
    }

    // Evaluate mechanisms
    for (const mechanism of parsed.mechanisms) {
      const match = await this.evaluateMechanism(mechanism, senderIP, domain);

      if (match) {
        return {
          result: this.qualifierToResult(mechanism.qualifier),
          domain,
          senderIP,
          mechanism,
          lookupCount: this.lookupCount,
        };
      }
    }

    // Handle redirect if no mechanisms matched
    if (parsed.redirect) {
      this.incrementLookup();
      const redirectResult = await this.checkDomain(senderIP, parsed.redirect, true);

      // Per RFC 7208, if redirect target has no SPF record, return permerror
      if (redirectResult.result === 'none') {
        return {
          result: 'permerror',
          domain,
          senderIP,
          explanation: `Redirect target ${parsed.redirect} has no SPF record`,
          lookupCount: this.lookupCount,
        };
      }

      return redirectResult;
    }

    // Default result is neutral
    return {
      result: 'neutral',
      domain,
      senderIP,
      lookupCount: this.lookupCount,
    };
  }

  /**
   * Evaluate a single mechanism against the sender IP
   */
  private async evaluateMechanism(
    mechanism: SPFMechanism,
    senderIP: string,
    domain: string
  ): Promise<boolean> {
    switch (mechanism.type) {
      case 'all':
        return true;

      case 'ip4':
        return this.matchIPv4(senderIP, mechanism.value!, mechanism.cidr);

      case 'ip6':
        return this.matchIPv6(senderIP, mechanism.value!, mechanism.cidr);

      case 'a':
        return this.matchA(senderIP, mechanism.value || domain, mechanism.cidr);

      case 'mx':
        return this.matchMX(senderIP, mechanism.value || domain, mechanism.cidr);

      case 'include':
        return this.matchInclude(senderIP, mechanism.value!);

      case 'ptr':
        // PTR is deprecated and should be avoided
        return false;

      case 'exists':
        return this.matchExists(mechanism.value!);

      default:
        return false;
    }
  }

  /**
   * Match sender IP against IPv4 mechanism
   */
  private matchIPv4(senderIP: string, network: string, cidr?: number): boolean {
    // Normalize IPv6-mapped IPv4
    const normalizedIP = senderIP.replace(/^::ffff:/, '');

    // Check if sender is IPv4
    if (!this.isIPv4(normalizedIP)) {
      return false;
    }

    const networkCIDR = cidr ?? 32;
    return this.ipInRange(normalizedIP, network, networkCIDR);
  }

  /**
   * Match sender IP against IPv6 mechanism
   */
  private matchIPv6(senderIP: string, network: string, cidr?: number): boolean {
    if (!this.isIPv6(senderIP)) {
      return false;
    }

    const networkCIDR = cidr ?? 128;
    return this.ipv6InRange(senderIP, network, networkCIDR);
  }

  /**
   * Match sender IP against A record mechanism
   */
  private async matchA(
    senderIP: string,
    targetDomain: string,
    cidr?: number
  ): Promise<boolean> {
    this.incrementLookup();

    const aRecords = await this.resolver.resolveA(targetDomain);

    for (const ip of aRecords) {
      if (this.matchIPv4(senderIP, ip, cidr ?? 32)) {
        return true;
      }
    }

    // Also check AAAA if sender is IPv6
    if (this.isIPv6(senderIP)) {
      const aaaaRecords = await this.resolver.resolveAAAA(targetDomain);
      for (const ip of aaaaRecords) {
        if (this.matchIPv6(senderIP, ip, cidr ?? 128)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Match sender IP against MX record mechanism
   */
  private async matchMX(
    senderIP: string,
    targetDomain: string,
    cidr?: number
  ): Promise<boolean> {
    this.incrementLookup();

    const mxRecords = await this.resolver.resolveMx(targetDomain);

    for (const mx of mxRecords) {
      this.incrementLookup();

      const aRecords = await this.resolver.resolveA(mx.exchange);
      for (const ip of aRecords) {
        if (this.matchIPv4(senderIP, ip, cidr ?? 32)) {
          return true;
        }
      }

      if (this.isIPv6(senderIP)) {
        const aaaaRecords = await this.resolver.resolveAAAA(mx.exchange);
        for (const ip of aaaaRecords) {
          if (this.matchIPv6(senderIP, ip, cidr ?? 128)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Match sender IP against include mechanism
   */
  private async matchInclude(senderIP: string, includeDomain: string): Promise<boolean> {
    this.incrementLookup();

    // Save current lookup count before include
    const result = await this.checkDomain(senderIP, includeDomain);

    // Include matches only on 'pass' result
    return result.result === 'pass';
  }

  /**
   * Match exists mechanism (domain must have A record)
   */
  private async matchExists(targetDomain: string): Promise<boolean> {
    this.incrementLookup();

    const aRecords = await this.resolver.resolveA(targetDomain);
    return aRecords.length > 0;
  }

  /**
   * Increment DNS lookup counter and check limit
   */
  private incrementLookup(): void {
    this.lookupCount++;
    if (this.lookupCount > MAX_DNS_LOOKUPS) {
      throw new Error(`DNS lookup limit exceeded (max ${MAX_DNS_LOOKUPS})`);
    }
  }

  /**
   * Convert qualifier to SPF result
   */
  private qualifierToResult(qualifier: '+' | '-' | '~' | '?'): SPFResult {
    switch (qualifier) {
      case '+': return 'pass';
      case '-': return 'fail';
      case '~': return 'softfail';
      case '?': return 'neutral';
    }
  }

  /**
   * Check if string is a valid IPv4 address
   */
  private isIPv4(ip: string): boolean {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;

    return parts.every(part => {
      const num = parseInt(part, 10);
      return !isNaN(num) && num >= 0 && num <= 255 && String(num) === part;
    });
  }

  /**
   * Check if string is a valid IPv6 address
   */
  private isIPv6(ip: string): boolean {
    // Simple check - contains colon and no dots (or is IPv4-mapped)
    return ip.includes(':') && (ip.includes('::') || ip.split(':').length === 8);
  }

  /**
   * Check if IPv4 address is in CIDR range
   */
  private ipInRange(ip: string, network: string, cidr: number): boolean {
    const ipNum = this.ipv4ToNumber(ip);
    const networkNum = this.ipv4ToNumber(network);

    // Handle /32 specially - JavaScript >>> 32 doesn't shift at all
    if (cidr === 32) {
      return ipNum === networkNum;
    }

    // Create mask: for /24, we want 0xFFFFFF00
    const mask = cidr === 0 ? 0 : ~((1 << (32 - cidr)) - 1);

    return (ipNum & mask) === (networkNum & mask);
  }

  /**
   * Convert IPv4 address to number
   */
  private ipv4ToNumber(ip: string): number {
    const parts = ip.split('.').map(Number);
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  }

  /**
   * Check if IPv6 address is in CIDR range
   */
  private ipv6InRange(ip: string, network: string, cidr: number): boolean {
    const ipBits = this.ipv6ToBits(ip);
    const networkBits = this.ipv6ToBits(network);

    // Compare first 'cidr' bits
    for (let i = 0; i < cidr && i < 128; i++) {
      if (ipBits[i] !== networkBits[i]) {
        return false;
      }
    }

    return true;
  }

  /**
   * Convert IPv6 address to bit array
   */
  private ipv6ToBits(ip: string): boolean[] {
    // Expand :: notation
    let expanded = ip;
    if (ip.includes('::')) {
      const parts = ip.split('::');
      const left = parts[0] ? parts[0].split(':') : [];
      const right = parts[1] ? parts[1].split(':') : [];
      const missing = 8 - left.length - right.length;
      const middle = new Array(missing).fill('0');
      expanded = [...left, ...middle, ...right].join(':');
    }

    const groups = expanded.split(':');
    const bits: boolean[] = [];

    for (const group of groups) {
      const num = parseInt(group || '0', 16);
      for (let i = 15; i >= 0; i--) {
        bits.push((num & (1 << i)) !== 0);
      }
    }

    return bits;
  }
}
