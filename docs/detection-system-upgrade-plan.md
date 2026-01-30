# Detection System Upgrade Plan: 68 → 93/100

## TDD Implementation Roadmap

**Goal**: Improve email classification system from 68/100 to 93/100 using strict Test-Driven Development

**Methodology**: Red-Green-Refactor cycle for every feature
1. **Red**: Write failing tests that define expected behavior
2. **Green**: Write minimal code to make tests pass
3. **Refactor**: Improve code quality while keeping tests green

---

## Phase Overview

| Phase | Focus | Points | Duration | Cumulative Score |
|-------|-------|--------|----------|------------------|
| 1 | Quick Wins | +5 | 2-3 days | 73/100 |
| 2 | URL Intelligence | +5 | 4-5 days | 78/100 |
| 3 | Sandbox & Attachments | +4 | 5-7 days | 82/100 |
| 4 | Visual Attack Detection | +5 | 4-5 days | 87/100 |
| 5 | Behavioral Intelligence | +4 | 5-6 days | 91/100 |
| 6 | Performance & Polish | +2 | 2-3 days | 93/100 |

**Total Estimated Duration**: 22-29 days

---

## Phase 1: Quick Wins (+5 points)

### 1.1 Expanded Brand Protection (+2 points)

**Test File**: `tests/detection/brand-protection.test.ts`

```typescript
// RED PHASE: Write these tests first (all should fail initially)

describe('Brand Protection - Expanded Coverage', () => {
  describe('Financial Institutions', () => {
    it('should detect fidelity.com typosquatting (fide1ity.com)', async () => {
      const result = await classifyURL('https://fide1ity.com/login', 'attacker.com');
      expect(result.type).toBe('malicious');
      expect(result.reason).toContain('Typosquatting');
    });

    it('should detect vanguard.com homoglyph (vαnguard.com)', async () => {
      const result = await classifyURL('https://vαnguard.com/accounts', 'attacker.com');
      expect(result.type).toBe('malicious');
      expect(result.score).toBeGreaterThanOrEqual(8);
    });

    it('should detect schwab.com cousin domain (schwab-secure.com)', async () => {
      const result = await classifyURL('https://schwab-secure.com', 'attacker.com');
      expect(result.type).toBe('malicious');
      expect(result.reason).toContain('cousin domain');
    });
  });

  describe('Enterprise Software', () => {
    it('should detect salesforce.com impersonation', async () => {
      const signals = await analyzeDomain('sa1esforce.com', 'Salesforce Support');
      expect(signals.some(s => s.type === 'homoglyph')).toBe(true);
    });

    it('should detect docusign.com impersonation', async () => {
      const signals = await analyzeDomain('docusign-documents.com', 'DocuSign');
      expect(signals.some(s => s.type === 'cousin_domain')).toBe(true);
    });

    it('should detect zoom.us impersonation (zo0m.us)', async () => {
      const signals = await analyzeDomain('zo0m.us', 'Zoom Meeting');
      expect(signals.some(s => s.type === 'homoglyph')).toBe(true);
    });
  });

  describe('Shipping & Logistics', () => {
    it('should detect fedex.com typosquatting', async () => {
      const result = await classifyURL('https://fedex-delivery.com/track', 'unknown.com');
      expect(result.type).toBe('malicious');
    });

    it('should detect ups.com typosquatting', async () => {
      const result = await classifyURL('https://ups-tracking.net/package', 'unknown.com');
      expect(result.type).toBe('malicious');
    });

    it('should detect usps.com typosquatting', async () => {
      const result = await classifyURL('https://usps-delivery.com', 'unknown.com');
      expect(result.type).toBe('malicious');
    });
  });

  describe('Common Typosquatting Patterns', () => {
    const typosquatPatterns = [
      { original: 'amazon', typos: ['amaz0n', 'amazom', 'arnazon', 'anazon'] },
      { original: 'microsoft', typos: ['micr0soft', 'mircosoft', 'microsft'] },
      { original: 'google', typos: ['g00gle', 'googie', 'gooogle', 'go0gle'] },
      { original: 'apple', typos: ['app1e', 'appie', 'aple'] },
    ];

    typosquatPatterns.forEach(({ original, typos }) => {
      typos.forEach(typo => {
        it(`should detect ${typo}.com as typosquatting of ${original}.com`, async () => {
          const result = await classifyURL(`https://${typo}.com`, 'attacker.com');
          expect(result.score).toBeGreaterThanOrEqual(7);
        });
      });
    });
  });
});
```

**Implementation File**: `lib/detection/brand-protection.ts`

```typescript
// GREEN PHASE: Implement after tests are written

/**
 * Expanded brand domains list - 65 high-value targets
 */
export const PROTECTED_BRANDS = {
  // Financial (20)
  financial: [
    'paypal.com', 'venmo.com', 'cashapp.com', 'zelle.com',
    'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
    'capitalone.com', 'usbank.com', 'pnc.com', 'tdbank.com',
    'fidelity.com', 'vanguard.com', 'schwab.com', 'etrade.com',
    'robinhood.com', 'coinbase.com', 'binance.com', 'kraken.com',
  ],

  // Tech Giants (15)
  tech: [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'meta.com', 'facebook.com', 'instagram.com', 'whatsapp.com',
    'twitter.com', 'x.com', 'linkedin.com', 'tiktok.com',
    'netflix.com', 'spotify.com', 'adobe.com',
  ],

  // Enterprise Software (15)
  enterprise: [
    'salesforce.com', 'workday.com', 'servicenow.com', 'oracle.com',
    'sap.com', 'slack.com', 'zoom.us', 'webex.com',
    'dropbox.com', 'box.com', 'docusign.com', 'atlassian.com',
    'github.com', 'gitlab.com', 'bitbucket.org',
  ],

  // Shipping (10)
  shipping: [
    'fedex.com', 'ups.com', 'usps.com', 'dhl.com',
    'amazon.com/shipping', 'ontrac.com', 'lasership.com',
    'purolator.com', 'canadapost.ca', 'royalmail.com',
  ],

  // Government & Healthcare (5)
    government: [
    'irs.gov', 'ssa.gov', 'medicare.gov', 'va.gov', 'usa.gov',
  ],
};

/**
 * Common typosquatting character substitutions
 */
export const TYPOSQUAT_SUBSTITUTIONS: Record<string, string[]> = {
  'a': ['4', '@', 'α', 'а', 'ɑ'],  // includes Cyrillic 'а'
  'b': ['8', 'ƅ', 'Ь'],
  'c': ['(', 'с', 'ϲ', '¢'],
  'd': ['cl', 'ԁ'],
  'e': ['3', 'е', 'ё', '℮'],
  'g': ['9', '6', 'ɡ'],
  'h': ['һ', 'հ'],
  'i': ['1', 'l', '|', 'і', 'ı'],
  'l': ['1', 'i', '|', 'ӏ'],
  'm': ['rn', 'м', 'ṃ'],
  'n': ['и', 'ո'],
  'o': ['0', 'о', 'ο', 'ө'],
  'p': ['р', 'ρ'],
  's': ['5', '$', 'ѕ'],
  't': ['7', '+', 'т'],
  'u': ['υ', 'ս', 'ü'],
  'v': ['ѵ', 'ν'],
  'w': ['vv', 'ѡ', 'ω'],
  'x': ['х', 'χ'],
  'y': ['у', 'ү'],
  'z': ['2', 'ᴢ'],
  '0': ['o', 'О'],
  '1': ['l', 'i', 'I'],
};

/**
 * Common cousin domain patterns
 */
export const COUSIN_DOMAIN_PATTERNS = [
  '{brand}-login',
  '{brand}-secure',
  '{brand}-verify',
  '{brand}-account',
  '{brand}-support',
  '{brand}-update',
  '{brand}-alert',
  '{brand}-notification',
  '{brand}online',
  '{brand}security',
  'login-{brand}',
  'secure-{brand}',
  'my{brand}',
  'get{brand}',
];
```

**Success Criteria**:
- [ ] All 65 brand domains added
- [ ] Typosquat detection accuracy > 95%
- [ ] Cousin domain detection accuracy > 90%
- [ ] Zero false positives on legitimate subdomains
- [ ] All tests pass

---

### 1.2 Tenant-Specific Configuration (+1 point)

**Test File**: `tests/detection/tenant-config.test.ts`

```typescript
describe('Tenant Configuration', () => {
  describe('Custom Thresholds', () => {
    it('should use tenant-specific suspicious threshold', async () => {
      const config = await getTenantConfig('tenant-high-security');
      expect(config.thresholds.suspicious).toBe(40); // Lower = more strict

      const verdict = await analyzeEmail(mockEmail, 'tenant-high-security');
      // Score of 45 should be suspicious for this tenant
      expect(verdict.verdict).toBe('suspicious');
    });

    it('should use tenant-specific quarantine threshold', async () => {
      const config = await getTenantConfig('tenant-low-security');
      expect(config.thresholds.quarantine).toBe(80); // Higher = more lenient

      const verdict = await analyzeEmail(mockEmail, 'tenant-low-security');
      // Score of 75 should pass for this tenant
      expect(verdict.verdict).toBe('suspicious'); // Not quarantine
    });

    it('should fall back to defaults for unconfigured tenants', async () => {
      const config = await getTenantConfig('new-tenant-123');
      expect(config.thresholds.suspicious).toBe(55);
      expect(config.thresholds.quarantine).toBe(73);
      expect(config.thresholds.block).toBe(85);
    });
  });

  describe('Custom Whitelists', () => {
    it('should respect tenant-specific domain whitelist', async () => {
      // Tenant has whitelisted partner-domain.com
      const email = mockEmailFrom('user@partner-domain.com');
      const verdict = await analyzeEmail(email, 'tenant-with-whitelist');
      expect(verdict.verdict).toBe('pass');
      expect(verdict.signals.some(s => s.type === 'tenant_whitelist')).toBe(true);
    });

    it('should respect tenant-specific sender whitelist', async () => {
      const email = mockEmailFrom('ceo@external-contractor.com');
      const verdict = await analyzeEmail(email, 'tenant-with-sender-whitelist');
      expect(verdict.verdict).toBe('pass');
    });
  });

  describe('Sensitivity Levels', () => {
    it('should apply high sensitivity multiplier', async () => {
      const configHigh = await getTenantConfig('high-sensitivity-tenant');
      expect(configHigh.sensitivityMultiplier).toBe(1.3);
    });

    it('should apply low sensitivity multiplier', async () => {
      const configLow = await getTenantConfig('low-sensitivity-tenant');
      expect(configLow.sensitivityMultiplier).toBe(0.8);
    });
  });
});
```

**Implementation File**: `lib/detection/tenant-config.ts`

```typescript
export interface TenantDetectionConfig {
  tenantId: string;
  thresholds: {
    suspicious: number;   // Default: 55
    quarantine: number;   // Default: 73
    block: number;        // Default: 85
  };
  whitelists: {
    domains: string[];
    senders: string[];
    subjectPatterns: string[];
  };
  blocklists: {
    domains: string[];
    senders: string[];
  };
  sensitivityLevel: 'low' | 'medium' | 'high';
  sensitivityMultiplier: number; // 0.8, 1.0, or 1.3
  features: {
    enableBECDetection: boolean;
    enableLLMAnalysis: boolean;
    enableSandbox: boolean;
  };
}

const DEFAULT_CONFIG: Omit<TenantDetectionConfig, 'tenantId'> = {
  thresholds: { suspicious: 55, quarantine: 73, block: 85 },
  whitelists: { domains: [], senders: [], subjectPatterns: [] },
  blocklists: { domains: [], senders: [] },
  sensitivityLevel: 'medium',
  sensitivityMultiplier: 1.0,
  features: { enableBECDetection: true, enableLLMAnalysis: true, enableSandbox: true },
};
```

**Success Criteria**:
- [ ] Tenant configs load from database
- [ ] Default fallback works correctly
- [ ] Whitelist/blocklist respected
- [ ] Sensitivity multiplier applied correctly
- [ ] All tests pass

---

### 1.3 QR Code Detection Foundation (+2 points)

**Test File**: `tests/detection/qr-scanner.test.ts`

```typescript
describe('QR Code Scanner', () => {
  describe('QR Code Extraction', () => {
    it('should extract QR code from inline base64 image', async () => {
      const html = `<img src="data:image/png;base64,${QR_CODE_BASE64_SAMPLE}" />`;
      const results = await extractQRCodes(html);
      expect(results.length).toBe(1);
      expect(results[0].decodedUrl).toBe('https://malicious-site.com/phish');
    });

    it('should extract multiple QR codes from email', async () => {
      const html = `
        <img src="data:image/png;base64,${QR_CODE_1}" />
        <img src="data:image/png;base64,${QR_CODE_2}" />
      `;
      const results = await extractQRCodes(html);
      expect(results.length).toBe(2);
    });

    it('should ignore non-QR images', async () => {
      const html = `<img src="data:image/png;base64,${REGULAR_IMAGE_BASE64}" />`;
      const results = await extractQRCodes(html);
      expect(results.length).toBe(0);
    });

    it('should handle QR codes with URL shorteners', async () => {
      const html = `<img src="data:image/png;base64,${QR_WITH_BITLY}" />`;
      const results = await extractQRCodes(html);
      expect(results[0].decodedUrl).toContain('bit.ly');
      expect(results[0].needsResolution).toBe(true);
    });
  });

  describe('QR Code Classification', () => {
    it('should flag QR code pointing to phishing domain', async () => {
      const qrResult = await classifyQRCode('https://paypa1-login.com/verify');
      expect(qrResult.classification.type).toBe('malicious');
      expect(qrResult.threatScore).toBeGreaterThanOrEqual(8);
    });

    it('should allow QR code pointing to legitimate domain', async () => {
      const qrResult = await classifyQRCode('https://linkedin.com/in/user123');
      expect(qrResult.classification.type).toBe('legitimate');
      expect(qrResult.threatScore).toBe(0);
    });

    it('should flag QR code with IP address URL', async () => {
      const qrResult = await classifyQRCode('http://192.168.1.100/payload');
      expect(qrResult.classification.type).toBe('malicious');
    });
  });

  describe('Pipeline Integration', () => {
    it('should add QR threat signal to email analysis', async () => {
      const email = mockEmailWithQRCode('https://malicious.com/steal');
      const verdict = await analyzeEmail(email, 'test-tenant');
      expect(verdict.signals.some(s => s.type === 'qr_code_threat')).toBe(true);
    });

    it('should not flag legitimate QR codes in newsletters', async () => {
      const email = mockNewsletterWithQRCode('https://company.com/app-download');
      const verdict = await analyzeEmail(email, 'test-tenant');
      expect(verdict.signals.filter(s => s.type === 'qr_code_threat')).toHaveLength(0);
    });
  });
});
```

**Implementation Files**:
```
lib/detection/qr/
├── index.ts           # Main exports
├── extractor.ts       # Extract QR codes from HTML/images
├── decoder.ts         # Decode QR code content
├── classifier.ts      # Classify decoded URLs
└── __fixtures__/      # Test QR code images
    ├── malicious-qr.png
    ├── legitimate-qr.png
    └── bitly-qr.png
```

**Success Criteria**:
- [ ] QR code extraction from base64 images works
- [ ] QR code decoding accuracy > 98%
- [ ] URL classification integration complete
- [ ] Pipeline signals added correctly
- [ ] All tests pass

---

## Phase 2: URL Intelligence (+5 points)

### 2.1 URL Shortener Resolution (+3 points)

**Test File**: `tests/detection/url-resolver.test.ts`

```typescript
describe('URL Shortener Resolution', () => {
  describe('Basic Resolution', () => {
    it('should resolve bit.ly URLs', async () => {
      const result = await resolveShortURL('https://bit.ly/3abc123');
      expect(result.finalUrl).toBeDefined();
      expect(result.redirectChain.length).toBeGreaterThanOrEqual(1);
    });

    it('should resolve tinyurl.com URLs', async () => {
      const result = await resolveShortURL('https://tinyurl.com/y1234abc');
      expect(result.finalUrl).toBeDefined();
    });

    it('should resolve t.co (Twitter) URLs', async () => {
      const result = await resolveShortURL('https://t.co/abc123');
      expect(result.finalUrl).toBeDefined();
    });

    it('should resolve goo.gl URLs', async () => {
      const result = await resolveShortURL('https://goo.gl/xyz789');
      expect(result.finalUrl).toBeDefined();
    });

    it('should handle ow.ly (Hootsuite) URLs', async () => {
      const result = await resolveShortURL('https://ow.ly/abcd1234');
      expect(result.finalUrl).toBeDefined();
    });
  });

  describe('Redirect Chain Analysis', () => {
    it('should capture full redirect chain', async () => {
      // bit.ly -> tracking.com -> final-destination.com
      const result = await resolveShortURL('https://bit.ly/multi-redirect');
      expect(result.redirectChain.length).toBeGreaterThanOrEqual(2);
      expect(result.redirectChain[0]).toContain('bit.ly');
    });

    it('should stop at maximum redirect depth (5)', async () => {
      const result = await resolveShortURL('https://bit.ly/infinite-redirect');
      expect(result.redirectChain.length).toBeLessThanOrEqual(5);
      expect(result.error).toContain('max redirects');
    });

    it('should detect redirect loops', async () => {
      const result = await resolveShortURL('https://bit.ly/redirect-loop');
      expect(result.isLoop).toBe(true);
      expect(result.isMalicious).toBe(true);
    });
  });

  describe('Threat Detection During Resolution', () => {
    it('should flag malicious final destination', async () => {
      const result = await resolveShortURL('https://bit.ly/to-phishing');
      expect(result.isMalicious).toBe(true);
      expect(result.threatReason).toContain('phishing');
    });

    it('should flag if any hop is malicious', async () => {
      // bit.ly -> malware-dropper.com -> legitimate.com
      const result = await resolveShortURL('https://bit.ly/through-malware');
      expect(result.isMalicious).toBe(true);
      expect(result.maliciousHop).toContain('malware-dropper');
    });

    it('should allow legitimate destinations', async () => {
      const result = await resolveShortURL('https://bit.ly/to-github');
      expect(result.isMalicious).toBe(false);
      expect(result.finalUrl).toContain('github.com');
    });
  });

  describe('Error Handling', () => {
    it('should handle timeout gracefully', async () => {
      const result = await resolveShortURL('https://bit.ly/slow-redirect', { timeout: 100 });
      expect(result.error).toContain('timeout');
      expect(result.isMalicious).toBe(false); // Don't flag on timeout
    });

    it('should handle DNS resolution failure', async () => {
      const result = await resolveShortURL('https://bit.ly/nonexistent-domain');
      expect(result.error).toContain('DNS');
    });

    it('should handle connection refused', async () => {
      const result = await resolveShortURL('https://bit.ly/connection-refused');
      expect(result.error).toBeDefined();
    });
  });

  describe('Caching', () => {
    it('should cache resolved URLs', async () => {
      const url = 'https://bit.ly/cached-url';
      await resolveShortURL(url);
      const cached = await resolveShortURL(url);
      expect(cached.fromCache).toBe(true);
    });

    it('should respect cache TTL', async () => {
      const url = 'https://bit.ly/expiring-cache';
      await resolveShortURL(url);
      // Simulate time passing
      jest.advanceTimersByTime(3600001); // 1 hour + 1ms
      const result = await resolveShortURL(url);
      expect(result.fromCache).toBe(false);
    });
  });
});
```

**Implementation File**: `lib/detection/url-resolver.ts`

```typescript
export interface URLResolutionResult {
  originalUrl: string;
  finalUrl: string | null;
  redirectChain: string[];
  isMalicious: boolean;
  maliciousHop?: string;
  threatReason?: string;
  isLoop: boolean;
  error?: string;
  fromCache: boolean;
  resolvedAt: Date;
}

export interface URLResolutionOptions {
  timeout?: number;        // Default: 5000ms
  maxRedirects?: number;   // Default: 5
  userAgent?: string;
  checkEachHop?: boolean;  // Default: true
}

const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'bitly.com',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'adf.ly',
  'bl.ink',
  'short.io',
  'rebrand.ly',
  'cutt.ly',
  'tiny.cc',
]);

export function isShortenerURL(url: string): boolean {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return SHORTENER_DOMAINS.has(hostname);
  } catch {
    return false;
  }
}

export async function resolveShortURL(
  url: string,
  options: URLResolutionOptions = {}
): Promise<URLResolutionResult> {
  // Implementation follows TDD - make tests pass
}
```

**Success Criteria**:
- [ ] Resolves all major shortener services
- [ ] Detects malicious destinations
- [ ] Handles redirect chains up to 5 hops
- [ ] Caching reduces API calls by 80%+
- [ ] All tests pass

---

### 2.2 Real-Time Threat Intelligence (+2 points)

**Test File**: `tests/detection/threat-intel.test.ts`

```typescript
describe('Threat Intelligence Integration', () => {
  describe('Google Safe Browsing', () => {
    it('should detect known phishing URLs', async () => {
      const result = await checkGoogleSafeBrowsing('https://known-phishing-site.com');
      expect(result.isThreat).toBe(true);
      expect(result.threatType).toBe('SOCIAL_ENGINEERING');
    });

    it('should detect malware URLs', async () => {
      const result = await checkGoogleSafeBrowsing('https://malware-distributor.com/payload.exe');
      expect(result.isThreat).toBe(true);
      expect(result.threatType).toBe('MALWARE');
    });

    it('should pass clean URLs', async () => {
      const result = await checkGoogleSafeBrowsing('https://google.com');
      expect(result.isThreat).toBe(false);
    });

    it('should batch multiple URL checks', async () => {
      const urls = ['https://site1.com', 'https://site2.com', 'https://site3.com'];
      const results = await batchCheckGoogleSafeBrowsing(urls);
      expect(results.length).toBe(3);
    });
  });

  describe('VirusTotal Integration', () => {
    it('should check URL reputation', async () => {
      const result = await checkVirusTotal('https://suspicious-domain.com');
      expect(result.positives).toBeDefined();
      expect(result.total).toBeDefined();
    });

    it('should check file hash', async () => {
      const hash = 'abc123def456...'; // Known malware hash
      const result = await checkVirusTotalHash(hash);
      expect(result.isMalware).toBe(true);
    });

    it('should respect rate limits', async () => {
      // Simulate hitting rate limit
      const results = await Promise.all(
        Array(10).fill(null).map(() => checkVirusTotal('https://test.com'))
      );
      expect(results.some(r => r.rateLimited)).toBe(true);
    });
  });

  describe('DNS Blocklist (SURBL/URIBL)', () => {
    it('should check SURBL for domain', async () => {
      const result = await checkSURBL('spam-domain.com');
      expect(result.isListed).toBeDefined();
    });

    it('should check URIBL for URL', async () => {
      const result = await checkURIBL('https://phishing-domain.com/login');
      expect(result.isListed).toBeDefined();
    });
  });

  describe('Aggregated Threat Check', () => {
    it('should aggregate results from multiple sources', async () => {
      const result = await checkThreatIntelligence('https://suspicious.com');
      expect(result.sources).toContain('google_safe_browsing');
      expect(result.sources).toContain('virustotal');
      expect(result.aggregateScore).toBeDefined();
    });

    it('should flag if any source reports threat', async () => {
      const result = await checkThreatIntelligence('https://known-bad.com');
      expect(result.isThreat).toBe(true);
    });

    it('should cache results for 1 hour', async () => {
      await checkThreatIntelligence('https://cached-check.com');
      const cached = await checkThreatIntelligence('https://cached-check.com');
      expect(cached.fromCache).toBe(true);
    });
  });
});
```

**Implementation Files**:
```
lib/detection/threat-intel/
├── index.ts                    # Aggregated threat check
├── google-safe-browsing.ts     # GSB API integration
├── virustotal.ts               # VT API integration
├── dns-blocklists.ts           # SURBL/URIBL checks
├── cache.ts                    # Redis caching layer
└── types.ts                    # Shared types
```

**Success Criteria**:
- [ ] Google Safe Browsing integration working
- [ ] VirusTotal integration with rate limiting
- [ ] DNS blocklist checks functional
- [ ] Aggregation logic correct
- [ ] Caching reduces API calls by 70%+
- [ ] All tests pass

---

## Phase 3: Sandbox & Attachments (+4 points)

### 3.1 Static File Analysis (+2 points)

**Test File**: `tests/detection/sandbox/static-analysis.test.ts`

```typescript
describe('Static File Analysis', () => {
  describe('PE File Analysis', () => {
    it('should detect packed executables', async () => {
      const result = await analyzeExecutable(PACKED_EXE_BUFFER);
      expect(result.isPacked).toBe(true);
      expect(result.packerType).toBeDefined();
    });

    it('should extract PE imports', async () => {
      const result = await analyzeExecutable(NORMAL_EXE_BUFFER);
      expect(result.imports).toContain('kernel32.dll');
    });

    it('should detect suspicious imports', async () => {
      const result = await analyzeExecutable(SUSPICIOUS_EXE_BUFFER);
      expect(result.suspiciousImports).toContain('CreateRemoteThread');
      expect(result.riskScore).toBeGreaterThan(5);
    });

    it('should check for known malware signatures', async () => {
      const result = await analyzeExecutable(KNOWN_MALWARE_BUFFER);
      expect(result.matchedSignatures.length).toBeGreaterThan(0);
    });
  });

  describe('Office Document Analysis', () => {
    it('should detect VBA macros in DOCM', async () => {
      const result = await analyzeOfficeDocument(DOCM_WITH_MACROS);
      expect(result.hasMacros).toBe(true);
      expect(result.macroCode).toBeDefined();
    });

    it('should detect auto-exec macros', async () => {
      const result = await analyzeOfficeDocument(DOCM_WITH_AUTOEXEC);
      expect(result.hasAutoExec).toBe(true);
      expect(result.autoExecTriggers).toContain('Document_Open');
    });

    it('should detect obfuscated VBA', async () => {
      const result = await analyzeOfficeDocument(DOCM_OBFUSCATED);
      expect(result.isObfuscated).toBe(true);
      expect(result.obfuscationScore).toBeGreaterThan(7);
    });

    it('should extract embedded objects', async () => {
      const result = await analyzeOfficeDocument(DOCX_WITH_OLE);
      expect(result.embeddedObjects.length).toBeGreaterThan(0);
    });

    it('should detect DDE attacks', async () => {
      const result = await analyzeOfficeDocument(DOCX_WITH_DDE);
      expect(result.hasDDE).toBe(true);
      expect(result.ddeCommand).toContain('cmd.exe');
    });
  });

  describe('PDF Analysis', () => {
    it('should detect JavaScript in PDF', async () => {
      const result = await analyzePDF(PDF_WITH_JS);
      expect(result.hasJavaScript).toBe(true);
      expect(result.jsCode).toBeDefined();
    });

    it('should detect embedded files', async () => {
      const result = await analyzePDF(PDF_WITH_EMBEDDED);
      expect(result.embeddedFiles.length).toBeGreaterThan(0);
    });

    it('should detect launch actions', async () => {
      const result = await analyzePDF(PDF_WITH_LAUNCH);
      expect(result.hasLaunchAction).toBe(true);
      expect(result.launchCommand).toBeDefined();
    });

    it('should detect obfuscation techniques', async () => {
      const result = await analyzePDF(PDF_OBFUSCATED);
      expect(result.obfuscationIndicators.length).toBeGreaterThan(0);
    });
  });

  describe('Archive Analysis', () => {
    it('should list files in ZIP', async () => {
      const result = await analyzeArchive(ZIP_BUFFER);
      expect(result.files.length).toBeGreaterThan(0);
    });

    it('should detect executables in archive', async () => {
      const result = await analyzeArchive(ZIP_WITH_EXE);
      expect(result.containsExecutables).toBe(true);
      expect(result.executableFiles).toContain('malware.exe');
    });

    it('should detect password-protected archives', async () => {
      const result = await analyzeArchive(PASSWORD_ZIP);
      expect(result.isPasswordProtected).toBe(true);
    });

    it('should detect zip bombs', async () => {
      const result = await analyzeArchive(ZIP_BOMB);
      expect(result.isZipBomb).toBe(true);
      expect(result.compressionRatio).toBeGreaterThan(100);
    });

    it('should recurse into nested archives', async () => {
      const result = await analyzeArchive(NESTED_ZIP, { maxDepth: 3 });
      expect(result.nestedArchives.length).toBeGreaterThan(0);
    });
  });
});
```

**Implementation Files**:
```
lib/detection/sandbox/
├── index.ts
├── static/
│   ├── pe-analyzer.ts        # Windows executable analysis
│   ├── office-analyzer.ts    # Office document analysis
│   ├── pdf-analyzer.ts       # PDF analysis
│   ├── archive-analyzer.ts   # ZIP/RAR/7z analysis
│   └── signatures.ts         # Known malware signatures
```

**Success Criteria**:
- [ ] PE analysis detects packers and suspicious imports
- [ ] Office analysis extracts and flags macros
- [ ] PDF analysis detects JavaScript and exploits
- [ ] Archive analysis handles nested content
- [ ] All tests pass

---

### 3.2 Dynamic Sandbox Execution (+2 points)

**Test File**: `tests/detection/sandbox/dynamic-analysis.test.ts`

```typescript
describe('Dynamic Sandbox Analysis', () => {
  describe('Sandbox Environment', () => {
    it('should create isolated VM for analysis', async () => {
      const sandbox = await createSandbox({ os: 'windows', timeout: 60000 });
      expect(sandbox.id).toBeDefined();
      expect(sandbox.status).toBe('ready');
    });

    it('should clean up sandbox after analysis', async () => {
      const sandbox = await createSandbox({ os: 'windows', timeout: 60000 });
      await analyzeSample(sandbox, SAMPLE_BUFFER);
      await destroySandbox(sandbox.id);
      const status = await getSandboxStatus(sandbox.id);
      expect(status).toBe('destroyed');
    });

    it('should timeout long-running samples', async () => {
      const sandbox = await createSandbox({ os: 'windows', timeout: 5000 });
      const result = await analyzeSample(sandbox, SLOW_SAMPLE);
      expect(result.timedOut).toBe(true);
    });
  });

  describe('Behavior Monitoring', () => {
    it('should detect file system modifications', async () => {
      const result = await analyzeSample(sandbox, DROPPER_SAMPLE);
      expect(result.behaviors.fileCreations.length).toBeGreaterThan(0);
      expect(result.behaviors.fileCreations).toContain(expect.stringContaining('AppData'));
    });

    it('should detect registry modifications', async () => {
      const result = await analyzeSample(sandbox, PERSISTENCE_SAMPLE);
      expect(result.behaviors.registryModifications.length).toBeGreaterThan(0);
      expect(result.behaviors.registryModifications).toContain(
        expect.stringContaining('Run')
      );
    });

    it('should detect process creation', async () => {
      const result = await analyzeSample(sandbox, PROCESS_SPAWN_SAMPLE);
      expect(result.behaviors.processCreations.length).toBeGreaterThan(0);
    });

    it('should detect network connections', async () => {
      const result = await analyzeSample(sandbox, C2_SAMPLE);
      expect(result.behaviors.networkConnections.length).toBeGreaterThan(0);
      expect(result.behaviors.networkConnections[0].destination).toBeDefined();
    });
  });

  describe('Threat Classification', () => {
    it('should classify ransomware behavior', async () => {
      const result = await analyzeSample(sandbox, RANSOMWARE_SAMPLE);
      expect(result.classification).toBe('ransomware');
      expect(result.indicators).toContain('mass_file_encryption');
    });

    it('should classify trojan behavior', async () => {
      const result = await analyzeSample(sandbox, TROJAN_SAMPLE);
      expect(result.classification).toBe('trojan');
      expect(result.indicators).toContain('backdoor_installation');
    });

    it('should classify cryptominer behavior', async () => {
      const result = await analyzeSample(sandbox, MINER_SAMPLE);
      expect(result.classification).toBe('cryptominer');
      expect(result.indicators).toContain('high_cpu_usage');
    });

    it('should classify clean samples', async () => {
      const result = await analyzeSample(sandbox, CLEAN_SAMPLE);
      expect(result.classification).toBe('clean');
      expect(result.riskScore).toBeLessThan(20);
    });
  });
});
```

**Implementation Files**:
```
lib/detection/sandbox/
├── dynamic/
│   ├── vm-manager.ts         # VM lifecycle management
│   ├── behavior-monitor.ts   # Process/file/network monitoring
│   ├── classifier.ts         # Behavior-based classification
│   └── report-generator.ts   # Analysis report generation
```

**Success Criteria**:
- [ ] VM isolation working
- [ ] Behavior monitoring captures all indicators
- [ ] Classification accuracy > 90%
- [ ] Timeout handling works correctly
- [ ] All tests pass

---

## Phase 4: Visual Attack Detection (+5 points)

### 4.1 Image OCR for Text-Based Attacks (+3 points)

**Test File**: `tests/detection/ocr/image-text.test.ts`

```typescript
describe('Image OCR Analysis', () => {
  describe('Text Extraction', () => {
    it('should extract text from PNG images', async () => {
      const result = await extractTextFromImage(PNG_WITH_TEXT);
      expect(result.text).toContain('Click here to verify');
    });

    it('should extract text from JPEG images', async () => {
      const result = await extractTextFromImage(JPEG_WITH_TEXT);
      expect(result.text.length).toBeGreaterThan(0);
    });

    it('should handle images embedded in HTML', async () => {
      const html = `<img src="data:image/png;base64,${TEXT_IMAGE_BASE64}" />`;
      const results = await extractTextFromEmailImages(html);
      expect(results.length).toBe(1);
      expect(results[0].extractedText.length).toBeGreaterThan(0);
    });

    it('should handle multiple images', async () => {
      const html = `
        <img src="${IMG1_URL}" />
        <img src="data:image/png;base64,${IMG2_BASE64}" />
      `;
      const results = await extractTextFromEmailImages(html);
      expect(results.length).toBe(2);
    });
  });

  describe('Threat Detection in Images', () => {
    it('should detect credential requests in images', async () => {
      const result = await analyzeImageText(IMAGE_WITH_PASSWORD_REQUEST);
      expect(result.threats).toContain('credential_request');
      expect(result.matchedPatterns).toContain(expect.stringMatching(/password/i));
    });

    it('should detect urgency language in images', async () => {
      const result = await analyzeImageText(IMAGE_WITH_URGENCY);
      expect(result.threats).toContain('urgency_language');
    });

    it('should detect financial requests in images', async () => {
      const result = await analyzeImageText(IMAGE_WITH_WIRE_TRANSFER);
      expect(result.threats).toContain('financial_request');
    });

    it('should detect brand impersonation in images', async () => {
      const result = await analyzeImageText(IMAGE_WITH_FAKE_LOGO);
      expect(result.threats).toContain('brand_impersonation');
      expect(result.impersonatedBrand).toBe('PayPal');
    });

    it('should not flag legitimate images', async () => {
      const result = await analyzeImageText(LEGITIMATE_NEWSLETTER_IMAGE);
      expect(result.threats.length).toBe(0);
    });
  });

  describe('Pipeline Integration', () => {
    it('should add image threat signals to analysis', async () => {
      const email = mockEmailWithImage(PHISHING_IMAGE);
      const verdict = await analyzeEmail(email, 'test-tenant');
      expect(verdict.signals.some(s => s.type === 'image_text_threat')).toBe(true);
    });

    it('should increase score for image-based phishing', async () => {
      const emailWithImage = mockEmailWithImage(PHISHING_IMAGE);
      const emailWithoutImage = mockEmailWithoutImage();

      const verdictWith = await analyzeEmail(emailWithImage, 'test-tenant');
      const verdictWithout = await analyzeEmail(emailWithoutImage, 'test-tenant');

      expect(verdictWith.overallScore).toBeGreaterThan(verdictWithout.overallScore);
    });
  });
});
```

**Implementation Files**:
```
lib/detection/ocr/
├── index.ts
├── extractor.ts          # Image extraction from HTML
├── tesseract-worker.ts   # Tesseract.js integration
├── text-analyzer.ts      # Threat pattern matching
└── brand-detector.ts     # Logo/brand detection
```

**Success Criteria**:
- [ ] OCR accuracy > 90% on clean images
- [ ] Threat pattern detection working
- [ ] Brand impersonation detection working
- [ ] Performance < 2s per image
- [ ] All tests pass

---

### 4.2 Enhanced QR Code Intelligence (+2 points)

**Test File**: `tests/detection/qr/advanced.test.ts`

```typescript
describe('Advanced QR Code Analysis', () => {
  describe('URL Resolution for QR Codes', () => {
    it('should resolve shortener URLs in QR codes', async () => {
      const result = await analyzeQRCode(QR_WITH_BITLY);
      expect(result.resolvedUrl).not.toContain('bit.ly');
      expect(result.redirectChain.length).toBeGreaterThan(0);
    });

    it('should flag malicious final destination', async () => {
      const result = await analyzeQRCode(QR_WITH_PHISHING);
      expect(result.isMalicious).toBe(true);
      expect(result.threatType).toBe('phishing');
    });
  });

  describe('QR Code Content Types', () => {
    it('should detect WiFi credentials in QR', async () => {
      const result = await analyzeQRCode(WIFI_QR);
      expect(result.contentType).toBe('wifi');
      expect(result.wifiSSID).toBeDefined();
    });

    it('should detect vCard in QR', async () => {
      const result = await analyzeQRCode(VCARD_QR);
      expect(result.contentType).toBe('vcard');
    });

    it('should detect phone numbers in QR', async () => {
      const result = await analyzeQRCode(PHONE_QR);
      expect(result.contentType).toBe('phone');
      expect(result.phoneNumber).toBeDefined();
    });
  });

  describe('Contextual Analysis', () => {
    it('should correlate QR URL with email sender', async () => {
      const email = mockEmailWithQR('https://sender-domain.com/legitimate');
      email.from.domain = 'sender-domain.com';
      const result = await analyzeEmail(email, 'test-tenant');
      expect(result.signals.some(s => s.type === 'qr_sender_match')).toBe(true);
    });

    it('should flag QR URL domain mismatch', async () => {
      const email = mockEmailWithQR('https://completely-different.com/phish');
      email.from.domain = 'legitimate-company.com';
      const result = await analyzeEmail(email, 'test-tenant');
      expect(result.signals.some(s => s.type === 'qr_domain_mismatch')).toBe(true);
    });
  });
});
```

**Success Criteria**:
- [ ] URL resolution for QR shorteners working
- [ ] Content type detection working
- [ ] Sender correlation working
- [ ] All tests pass

---

## Phase 5: Behavioral Intelligence (+4 points)

### 5.1 Anomaly Detection for Trusted Senders (+3 points)

**Test File**: `tests/detection/anomaly/sender-baseline.test.ts`

```typescript
describe('Sender Anomaly Detection', () => {
  describe('Baseline Building', () => {
    it('should build baseline from historical emails', async () => {
      const baseline = await buildSenderBaseline('sender@company.com', 'tenant-123');
      expect(baseline.typicalSendTimes).toBeDefined();
      expect(baseline.typicalSubjectPatterns).toBeDefined();
      expect(baseline.historicalDomains).toBeDefined();
    });

    it('should require minimum email count for baseline', async () => {
      const baseline = await buildSenderBaseline('new-sender@company.com', 'tenant-123');
      expect(baseline.hasBaseline).toBe(false);
      expect(baseline.emailCount).toBeLessThan(10);
    });
  });

  describe('Time Anomaly Detection', () => {
    it('should detect unusual send time', async () => {
      const baseline = mockBaseline({ typicalSendTimes: { start: 9, end: 17 } });
      const email = mockEmail({ sentAt: '03:00:00Z' }); // 3 AM
      const anomaly = detectTimeAnomaly(email, baseline);
      expect(anomaly.isAnomaly).toBe(true);
      expect(anomaly.reason).toContain('unusual time');
    });

    it('should allow normal send times', async () => {
      const baseline = mockBaseline({ typicalSendTimes: { start: 9, end: 17 } });
      const email = mockEmail({ sentAt: '14:00:00Z' }); // 2 PM
      const anomaly = detectTimeAnomaly(email, baseline);
      expect(anomaly.isAnomaly).toBe(false);
    });
  });

  describe('Content Anomaly Detection', () => {
    it('should detect unusual URL domains', async () => {
      const baseline = mockBaseline({
        historicalDomains: ['company.com', 'trusted-partner.com']
      });
      const email = mockEmailWithURLs(['https://never-seen-before.com/download']);
      const anomaly = detectContentAnomaly(email, baseline);
      expect(anomaly.hasUnusualDomains).toBe(true);
      expect(anomaly.unusualDomains).toContain('never-seen-before.com');
    });

    it('should detect unusual attachment types', async () => {
      const baseline = mockBaseline({
        typicalAttachments: ['pdf', 'docx', 'xlsx']
      });
      const email = mockEmailWithAttachment('payload.exe');
      const anomaly = detectContentAnomaly(email, baseline);
      expect(anomaly.hasUnusualAttachment).toBe(true);
    });

    it('should detect subject pattern deviation', async () => {
      const baseline = mockBaseline({
        typicalSubjectPatterns: ['Weekly Report', 'Monthly Summary', 'Invoice #']
      });
      const email = mockEmail({ subject: 'URGENT: Wire Transfer Needed' });
      const anomaly = detectContentAnomaly(email, baseline);
      expect(anomaly.hasUnusualSubject).toBe(true);
    });
  });

  describe('Behavioral Scoring', () => {
    it('should calculate anomaly score', async () => {
      const email = mockEmail({
        sentAt: '03:00:00Z',
        subject: 'URGENT ACTION REQUIRED',
        urls: ['https://suspicious-domain.com']
      });
      const baseline = mockBaseline({
        typicalSendTimes: { start: 9, end: 17 },
        typicalSubjectPatterns: ['Monthly Report'],
        historicalDomains: ['trusted.com']
      });

      const anomalyScore = calculateAnomalyScore(email, baseline);
      expect(anomalyScore).toBeGreaterThan(50); // High anomaly
    });

    it('should not penalize normal behavior', async () => {
      const email = mockEmail({
        sentAt: '14:00:00Z',
        subject: 'Monthly Report Q4',
        urls: ['https://trusted.com/report']
      });
      const baseline = mockBaseline({
        typicalSendTimes: { start: 9, end: 17 },
        typicalSubjectPatterns: ['Monthly Report'],
        historicalDomains: ['trusted.com']
      });

      const anomalyScore = calculateAnomalyScore(email, baseline);
      expect(anomalyScore).toBeLessThan(10); // Low anomaly
    });
  });

  describe('Pipeline Integration', () => {
    it('should add anomaly signals for trusted but suspicious emails', async () => {
      const email = mockTrustedSenderEmail({
        sentAt: '03:00:00Z',
        subject: 'URGENT: Send Bitcoin NOW',
        urls: ['https://suspicious-crypto.com']
      });

      const verdict = await analyzeEmail(email, 'test-tenant');
      expect(verdict.signals.some(s => s.type === 'sender_anomaly')).toBe(true);
    });

    it('should not bypass trusted sender protection for normal emails', async () => {
      const email = mockTrustedSenderEmail({
        sentAt: '14:00:00Z',
        subject: 'Weekly Status Update',
        urls: ['https://company.com/dashboard']
      });

      const verdict = await analyzeEmail(email, 'test-tenant');
      expect(verdict.signals.some(s => s.type === 'sender_anomaly')).toBe(false);
    });
  });
});
```

**Implementation Files**:
```
lib/detection/anomaly/
├── index.ts
├── baseline-builder.ts      # Build sender baselines
├── time-analyzer.ts         # Time-based anomaly detection
├── content-analyzer.ts      # Content-based anomaly detection
├── scorer.ts                # Anomaly scoring
└── storage.ts               # Baseline persistence
```

**Success Criteria**:
- [ ] Baseline building from 10+ emails working
- [ ] Time anomaly detection accurate
- [ ] Content anomaly detection working
- [ ] Integration with pipeline complete
- [ ] All tests pass

---

### 5.2 Feedback Learning Improvements (+1 point)

**Test File**: `tests/feedback/learning-improvements.test.ts`

```typescript
describe('Enhanced Feedback Learning', () => {
  describe('Real-Time Rule Updates', () => {
    it('should apply rule within 1 minute of creation', async () => {
      const rule = await createFeedbackRule({
        type: 'domain_whitelist',
        value: 'new-partner.com',
        tenantId: 'test-tenant'
      });

      // Wait 1 minute
      await sleep(60000);

      const email = mockEmailFrom('user@new-partner.com');
      const verdict = await analyzeEmail(email, 'test-tenant');
      expect(verdict.signals.some(s =>
        s.type === 'feedback_learning' && s.detail?.includes('new-partner.com')
      )).toBe(true);
    });
  });

  describe('Pattern Discovery', () => {
    it('should auto-discover false positive patterns', async () => {
      // Simulate multiple false positive reports for same pattern
      await reportFalsePositive('test-tenant', mockEmail1);
      await reportFalsePositive('test-tenant', mockEmail2);
      await reportFalsePositive('test-tenant', mockEmail3);

      const patterns = await discoverFalsePositivePatterns('test-tenant');
      expect(patterns.length).toBeGreaterThan(0);
    });
  });
});
```

**Success Criteria**:
- [ ] Rule updates apply within 1 minute
- [ ] Pattern discovery working
- [ ] All tests pass

---

## Phase 6: Performance & Polish (+2 points)

### 6.1 Parallel Layer Execution (+2 points)

**Test File**: `tests/detection/pipeline-performance.test.ts`

```typescript
describe('Pipeline Performance', () => {
  describe('Parallel Execution', () => {
    it('should run independent layers in parallel', async () => {
      const startTime = Date.now();
      const verdict = await analyzeEmail(mockEmail, 'test-tenant');
      const duration = Date.now() - startTime;

      // Sequential would be ~5000ms (5 layers * 1s each)
      // Parallel should be ~2000ms (longest single layer)
      expect(duration).toBeLessThan(3000);
    });

    it('should still respect layer dependencies', async () => {
      const verdict = await analyzeEmail(mockEmail, 'test-tenant');

      // LLM should have access to prior layer results
      const llmSignal = verdict.signals.find(s => s.type === 'llm_analysis');
      expect(llmSignal?.metadata?.priorLayerScores).toBeDefined();
    });
  });

  describe('Latency Benchmarks', () => {
    it('should analyze simple email in < 500ms', async () => {
      const startTime = Date.now();
      await analyzeEmail(simpleEmail, 'test-tenant');
      expect(Date.now() - startTime).toBeLessThan(500);
    });

    it('should analyze complex email in < 3000ms', async () => {
      const startTime = Date.now();
      await analyzeEmail(complexEmail, 'test-tenant');
      expect(Date.now() - startTime).toBeLessThan(3000);
    });
  });
});
```

**Implementation**: Modify `pipeline.ts` to use `Promise.all` for independent layers.

**Success Criteria**:
- [ ] 40-60% latency reduction achieved
- [ ] Layer dependencies preserved
- [ ] All tests pass

---

## Test Coverage Requirements

| Component | Minimum Coverage |
|-----------|------------------|
| URL Classifier | 95% |
| Brand Protection | 95% |
| URL Resolver | 90% |
| Threat Intel | 85% |
| Static Analysis | 90% |
| Dynamic Sandbox | 80% |
| OCR | 85% |
| QR Scanner | 90% |
| Anomaly Detection | 90% |
| Pipeline | 95% |

---

## Running Tests

```bash
# Run all detection tests
npm run test -- --testPathPattern="tests/detection"

# Run specific phase tests
npm run test -- --testPathPattern="tests/detection/brand-protection"
npm run test -- --testPathPattern="tests/detection/url-resolver"
npm run test -- --testPathPattern="tests/detection/sandbox"

# Run with coverage
npm run test -- --coverage --testPathPattern="tests/detection"

# Watch mode during development
npm run test -- --watch --testPathPattern="tests/detection/qr"
```

---

## Success Metrics

### Phase Completion Checklist

- [ ] **Phase 1 Complete**: All quick win tests passing, coverage > 90%
- [ ] **Phase 2 Complete**: URL intelligence tests passing, coverage > 85%
- [ ] **Phase 3 Complete**: Sandbox tests passing, coverage > 85%
- [ ] **Phase 4 Complete**: Visual attack tests passing, coverage > 85%
- [ ] **Phase 5 Complete**: Behavioral tests passing, coverage > 90%
- [ ] **Phase 6 Complete**: Performance benchmarks met

### Final Validation

1. Re-run original false positive test case (VCI Approval email)
2. Run full regression test suite
3. Benchmark latency on 1000 email sample
4. Calculate new system rating
5. Document any remaining gaps

---

## Dependencies & Prerequisites

### NPM Packages to Install

```bash
# Phase 1
npm install --save-dev @types/jest

# Phase 2
npm install node-fetch redis

# Phase 3
npm install pe-parser oletools pdf-parser node-stream-zip
npm install --save-dev @types/pe-parser

# Phase 4
npm install tesseract.js jsqr

# Phase 5
npm install date-fns
```

### External Services Required

- **Phase 2**: Google Safe Browsing API key, VirusTotal API key
- **Phase 3**: Cloud sandbox provider (e.g., Cuckoo, Any.Run API)
- **Phase 5**: Redis for baseline caching

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| API rate limits | Aggressive caching, request batching |
| Sandbox escape | Use reputable cloud sandbox, not self-hosted |
| OCR accuracy | Multiple passes, confidence thresholds |
| False positives | Extensive test cases, gradual rollout |
| Performance regression | Benchmark tests in CI pipeline |

---

*Document Version: 1.0*
*Created: 2025-01-29*
*Target Completion: +22-29 days*
