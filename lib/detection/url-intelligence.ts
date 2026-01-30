/**
 * URL Intelligence Module - Phase 2
 *
 * Advanced URL analysis for threat detection:
 * - Domain age intelligence
 * - Lookalike domain detection
 * - URL obfuscation detection
 * - Redirect chain analysis
 *
 * Expected Impact: +5 detection points
 */

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface DomainAgeResult {
  domain: string;
  isNewDomain: boolean;
  ageDays: number;
  riskScore: number;
  signals: string[];
  registrar?: string;
  privacyProtected?: boolean;
}

export interface LookalikeResult {
  domain: string;
  isLookalike: boolean;
  targetDomain?: string;
  technique?: string;
  riskScore: number;
  signals: string[];
  similarity?: number;
}

export interface ObfuscationResult {
  url: string;
  isObfuscated: boolean;
  technique?: string;
  riskScore: number;
  signals: string[];
  decodedUrl?: string;
}

export interface RedirectChainResult {
  urls: string[];
  chainLength: number;
  isSuspicious: boolean;
  riskScore: number;
  signals: string[];
  finalDestination?: string;
}

export interface URLIntelligenceResult {
  url: string;
  overallRiskScore: number;
  verdict: 'safe' | 'suspicious' | 'malicious';
  signals: string[];
  parseError?: boolean;
  domainAge?: DomainAgeResult;
  lookalike?: LookalikeResult;
  obfuscation?: ObfuscationResult;
  redirectChain?: RedirectChainResult;
  breakdown: {
    domainAge?: number;
    lookalike?: number;
    obfuscation?: number;
    redirectChain?: number;
  };
}

export interface WHOISData {
  createdDate?: Date;
  registrar?: string;
  privacyProtected?: boolean;
}

export interface URLIntelligenceOptions {
  checkDomainAge?: boolean;
  checkLookalike?: boolean;
  checkObfuscation?: boolean;
  checkRedirectChain?: boolean;
  whoisData?: WHOISData;
  redirectChain?: string[];
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Well-known brand domains for lookalike detection
 */
const PROTECTED_BRANDS: Record<string, string[]> = {
  'google.com': ['google', 'gmail', 'goog1e', 'g00gle', 'gooogle', 'gogle', 'gogole'],
  'microsoft.com': ['microsoft', 'msft', 'micros0ft', 'micr0s0ft', 'micr0soft', 'microsofl', 'microsft', 'micosoft', 'mlcrosoft'],
  'apple.com': ['apple', 'app1e', 'appie', 'aple', 'aplle'],
  'amazon.com': ['amazon', 'amaz0n', 'arnazon', 'amazom', 'amazn'],
  'facebook.com': ['facebook', 'faceb00k', 'facebok', 'faebook'],
  'paypal.com': ['paypal', 'paypa1', 'paypai', 'papal', 'pay-pal'],
  'netflix.com': ['netflix', 'netf1ix', 'netflik', 'netfilx'],
  'dropbox.com': ['dropbox', 'dr0pbox', 'dropb0x'],
  'linkedin.com': ['linkedin', '1inkedin', 'linkedln'],
  'twitter.com': ['twitter', 'twltter', 'tw1tter'],
  'instagram.com': ['instagram', '1nstagram', 'instagran'],
  'chase.com': ['chase', 'chasee', 'chasse'],
  'wellsfargo.com': ['wellsfargo', 'we11sfargo', 'welsfargo'],
  'bankofamerica.com': ['bankofamerica', 'bank0famerica', 'bankofamerrica'],
  'citibank.com': ['citibank', 'c1tibank', 'citibanck'],
  'usps.com': ['usps', 'uspss', 'ussp'],
  'fedex.com': ['fedex', 'fed3x', 'fedx'],
  'ups.com': ['ups', 'upps'],
  'dhl.com': ['dhl', 'dh1'],
};

/**
 * High-risk TLDs commonly used in phishing
 */
const HIGH_RISK_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', // Free TLDs
  '.xyz', '.top', '.work', '.click', // Cheap TLDs
  '.ru', '.cn', '.su', // Country TLDs with abuse
  '.info', '.biz', // Commonly abused
];

/**
 * Reputable registrars that lower risk
 */
const REPUTABLE_REGISTRARS = [
  'markmonitor',
  'corporatedomains',
  'cscglobal',
  'network solutions',
  'verisign',
];

/**
 * URL shortener domains
 */
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'rebrand.ly', 'cutt.ly', 'short.link',
];

/**
 * Homoglyph character mappings (lookalike characters)
 */
const HOMOGLYPHS: Record<string, string[]> = {
  'a': ['а', 'ạ', 'ą', 'ä', 'α'],
  'c': ['с', 'ç', 'ć'],
  'd': ['ԁ', 'ð'],
  'e': ['е', 'ё', 'ę', 'ė', 'ε'],
  'g': ['ɡ', 'ġ'],
  'h': ['һ', 'ħ'],
  'i': ['і', 'ı', 'ị', 'ï'],
  'j': ['ј', 'ĵ'],
  'k': ['κ', 'к'],
  'l': ['ӏ', 'ł', '1', '|'],
  'm': ['м', 'ṃ'],
  'n': ['п', 'ñ'],
  'o': ['о', 'ο', 'ọ', '0', 'ö'],
  'p': ['р', 'ρ'],
  'q': ['ԛ', 'գ'],
  'r': ['г', 'ŕ'],
  's': ['ѕ', 'ś', '$'],
  't': ['т', 'ţ'],
  'u': ['υ', 'ц', 'ù'],
  'v': ['ν', 'ѵ'],
  'w': ['ω', 'ш'],
  'x': ['х', 'ҳ'],
  'y': ['у', 'ý'],
  'z': ['ᴢ', 'ż'],
};

// ============================================================================
// Domain Age Intelligence
// ============================================================================

/**
 * Analyze domain age and registration details
 */
export function analyzeDomainAge(domain: string, whoisData: WHOISData): DomainAgeResult {
  const signals: string[] = [];
  let riskScore = 0;

  // Handle unknown/missing WHOIS data
  if (!whoisData.createdDate) {
    return {
      domain,
      isNewDomain: false,
      ageDays: -1,
      riskScore: 3, // Moderate risk when unknown
      signals: ['unknown_whois_data'],
    };
  }

  const now = new Date();
  const ageDays = Math.floor((now.getTime() - whoisData.createdDate.getTime()) / (1000 * 60 * 60 * 24));

  // Age-based risk scoring
  let isNewDomain = false;
  if (ageDays < 30) {
    riskScore += 7;
    isNewDomain = true;
    signals.push('newly_registered_domain');
  } else if (ageDays < 90) {
    riskScore += 4;
    isNewDomain = true;
    signals.push('recently_registered_domain');
  } else if (ageDays < 180) {
    riskScore += 2;
    signals.push('moderately_new_domain');
  }

  // Privacy protection increases suspicion slightly
  if (whoisData.privacyProtected) {
    riskScore += 1;
    signals.push('privacy_protected_whois');
  }

  // Reputable registrars decrease risk
  if (whoisData.registrar) {
    const registrarLower = whoisData.registrar.toLowerCase();
    const isReputable = REPUTABLE_REGISTRARS.some(r => registrarLower.includes(r));
    if (isReputable) {
      riskScore = Math.max(0, riskScore - 2);
      signals.push('reputable_registrar');
    }
  }

  return {
    domain,
    isNewDomain,
    ageDays,
    riskScore: Math.min(10, riskScore),
    signals,
    registrar: whoisData.registrar,
    privacyProtected: whoisData.privacyProtected,
  };
}

// ============================================================================
// Lookalike Domain Detection
// ============================================================================

/**
 * Detect lookalike/typosquatting domains
 */
export function detectLookalikeDomain(domain: string): LookalikeResult {
  // Handle null/undefined
  if (!domain) {
    return {
      domain: '',
      isLookalike: false,
      riskScore: 0,
      signals: [],
    };
  }

  const signals: string[] = [];
  let riskScore = 0;
  let isLookalike = false;
  let targetDomain: string | undefined;
  let technique: string | undefined;

  // Normalize domain
  const domainLower = domain.toLowerCase();

  // Check for high-risk TLDs
  const hasHighRiskTLD = HIGH_RISK_TLDS.some(tld => domainLower.endsWith(tld));
  if (hasHighRiskTLD) {
    riskScore += 5;
    signals.push('high_risk_tld');
  }

  // Check for internationalized domain name
  if (/[^\x00-\x7F]/.test(domain) || domain.includes('xn--')) {
    signals.push('internationalized_domain');

    // Check for homoglyph attack
    const asciiEquivalent = convertHomoglyphsToAscii(domain);
    if (asciiEquivalent !== domain.toLowerCase()) {
      // Check if ASCII equivalent matches a brand
      for (const [brand, variations] of Object.entries(PROTECTED_BRANDS)) {
        const brandName = brand.replace('.com', '');
        if (asciiEquivalent.includes(brandName)) {
          isLookalike = true;
          targetDomain = brand;
          technique = 'homoglyph';
          riskScore = Math.max(riskScore, 9);
          signals.push('homoglyph_attack');
          break;
        }
      }
    }
  }

  // Check for brand impersonation
  if (!isLookalike) {
    const result = checkBrandImpersonation(domainLower);
    if (result.isLookalike) {
      isLookalike = true;
      targetDomain = result.targetDomain;
      technique = result.technique;
      riskScore = Math.max(riskScore, result.riskScore);
      signals.push(...result.signals);
    }
  }

  // Check for subdomain impersonation (e.g., login.microsoft.attacker.com)
  if (!isLookalike) {
    const result = checkSubdomainImpersonation(domainLower);
    if (result.isLookalike) {
      isLookalike = true;
      targetDomain = result.targetDomain;
      technique = 'subdomain_impersonation';
      riskScore = Math.max(riskScore, 8);
      signals.push('subdomain_impersonation');
    }
  }

  // Check for brand keywords in non-brand domains
  if (!isLookalike) {
    const result = checkBrandKeywords(domainLower);
    if (result.found) {
      isLookalike = true;
      targetDomain = result.targetDomain;
      technique = 'brand_keyword';
      riskScore = Math.max(riskScore, 6);
      signals.push('brand_keyword_in_domain');
      if (result.multipleBrands) {
        signals.push('multiple_brand_keywords');
        riskScore = Math.max(riskScore, 8);
      }
    }
  }

  return {
    domain,
    isLookalike,
    targetDomain,
    technique,
    riskScore: Math.min(10, riskScore),
    signals,
  };
}

/**
 * Convert homoglyph characters to ASCII equivalents
 */
function convertHomoglyphsToAscii(text: string): string {
  let result = text.toLowerCase();
  for (const [ascii, glyphs] of Object.entries(HOMOGLYPHS)) {
    for (const glyph of glyphs) {
      // Use split/join for reliable replacement of unicode characters
      result = result.split(glyph).join(ascii);
    }
  }
  return result;
}

/**
 * Check for brand impersonation using various techniques
 */
function checkBrandImpersonation(domain: string): {
  isLookalike: boolean;
  targetDomain?: string;
  technique?: string;
  riskScore: number;
  signals: string[];
} {
  const domainParts = domain.split('.');
  const tld = domainParts.slice(-1)[0];
  const baseDomain = domainParts.slice(0, -1).join('.');

  for (const [brand, variations] of Object.entries(PROTECTED_BRANDS)) {
    const brandName = brand.replace('.com', '');

    // Check if domain is the actual brand
    if (domain === brand || domain === `www.${brand}`) {
      return { isLookalike: false, riskScore: 0, signals: [] };
    }

    // IMPORTANT: Check specific techniques BEFORE variations list
    // This ensures we detect the correct technique (addition, omission, etc.)
    // instead of generic 'character_substitution'

    // Order matters! Check in this sequence:
    // 1. TLD substitution (exact brand name, different TLD)
    // 2. Hyphen insertion (contains hyphen, removing gives brand name)
    // 3. Character addition/omission/transposition

    // Check for TLD substitution FIRST (e.g., google.co instead of google.com)
    // Note: .co is commonly used for .com typosquatting
    if (baseDomain === brandName && tld !== 'com') {
      // Only allow truly legitimate ccTLDs (not .co which is often typosquatting)
      if (!['org', 'net', 'io', 'uk', 'de', 'fr', 'jp', 'au', 'ca'].includes(tld)) {
        return {
          isLookalike: true,
          targetDomain: brand,
          technique: 'tld_substitution',
          riskScore: 6,
          signals: ['tld_substitution'],
        };
      }
    }

    // Check for hyphen insertion (must actually contain a hyphen)
    if (baseDomain.includes('-') && baseDomain.replace(/-/g, '') === brandName) {
      return {
        isLookalike: true,
        targetDomain: brand,
        technique: 'hyphen_insertion',
        riskScore: 7,
        signals: ['hyphen_insertion'],
      };
    }

    // Check for character addition (extra letter, but not a hyphen)
    if (!baseDomain.includes('-') && hasExtraCharacter(baseDomain, brandName)) {
      return {
        isLookalike: true,
        targetDomain: brand,
        technique: 'character_addition',
        riskScore: 7,
        signals: ['character_addition'],
      };
    }

    // Check for character omission
    if (hasOmittedCharacter(baseDomain, brandName)) {
      return {
        isLookalike: true,
        targetDomain: brand,
        technique: 'character_omission',
        riskScore: 7,
        signals: ['character_omission'],
      };
    }

    // Check for transposition (swapped characters)
    if (hasTransposition(baseDomain, brandName)) {
      return {
        isLookalike: true,
        targetDomain: brand,
        technique: 'transposition',
        riskScore: 7,
        signals: ['transposition'],
      };
    }

    // Check for character substitution (0 for o, 1 for l, etc.)
    // This is checked AFTER specific techniques to avoid false classification
    for (const variation of variations) {
      if (baseDomain === variation || baseDomain.includes(variation)) {
        if (variation !== brandName) {
          return {
            isLookalike: true,
            targetDomain: brand,
            technique: 'character_substitution',
            riskScore: 8,
            signals: ['character_substitution'],
          };
        }
      }
    }
  }

  return { isLookalike: false, riskScore: 0, signals: [] };
}

/**
 * Check if domain has one extra character compared to brand
 */
function hasExtraCharacter(domain: string, brand: string): boolean {
  if (domain.length !== brand.length + 1) return false;

  for (let i = 0; i < domain.length; i++) {
    const withoutChar = domain.slice(0, i) + domain.slice(i + 1);
    if (withoutChar === brand) return true;
  }
  return false;
}

/**
 * Check if domain has one omitted character compared to brand
 */
function hasOmittedCharacter(domain: string, brand: string): boolean {
  if (domain.length !== brand.length - 1) return false;

  for (let i = 0; i < brand.length; i++) {
    const withoutChar = brand.slice(0, i) + brand.slice(i + 1);
    if (withoutChar === domain) return true;
  }
  return false;
}

/**
 * Check if domain has transposed characters compared to brand
 */
function hasTransposition(domain: string, brand: string): boolean {
  if (domain.length !== brand.length) return false;

  for (let i = 0; i < brand.length - 1; i++) {
    const transposed = brand.slice(0, i) + brand[i + 1] + brand[i] + brand.slice(i + 2);
    if (transposed === domain) return true;
  }
  return false;
}

/**
 * Check for subdomain impersonation
 */
function checkSubdomainImpersonation(domain: string): {
  isLookalike: boolean;
  targetDomain?: string;
} {
  const parts = domain.split('.');

  // Need at least 3 parts (subdomain.brand.attacker.com)
  if (parts.length < 4) {
    return { isLookalike: false };
  }

  // Check if any subdomain part is a brand name
  for (const brand of Object.keys(PROTECTED_BRANDS)) {
    const brandName = brand.replace('.com', '');
    for (let i = 0; i < parts.length - 2; i++) {
      if (parts[i] === brandName || parts[i].includes(brandName)) {
        // The actual domain (last two parts) should not be the brand
        const actualDomain = parts.slice(-2).join('.');
        if (actualDomain !== brand) {
          return {
            isLookalike: true,
            targetDomain: brand,
          };
        }
      }
    }
  }

  return { isLookalike: false };
}

/**
 * Check for brand keywords in domain
 */
function checkBrandKeywords(domain: string): {
  found: boolean;
  targetDomain?: string;
  multipleBrands: boolean;
} {
  const foundBrands: string[] = [];

  for (const brand of Object.keys(PROTECTED_BRANDS)) {
    const brandName = brand.replace('.com', '');

    // Skip if domain IS the brand
    if (domain === brand || domain === `www.${brand}`) continue;

    // Check if brand name appears in a different domain
    if (domain.includes(brandName) && !domain.endsWith(brand)) {
      foundBrands.push(brand);
    }
  }

  if (foundBrands.length === 0) {
    return { found: false, multipleBrands: false };
  }

  return {
    found: true,
    targetDomain: foundBrands[0],
    multipleBrands: foundBrands.length > 1,
  };
}

// ============================================================================
// URL Obfuscation Detection
// ============================================================================

/**
 * Detect URL obfuscation techniques
 */
export function detectURLObfuscation(url: string): ObfuscationResult {
  // Handle null/undefined
  if (!url) {
    return {
      url: '',
      isObfuscated: false,
      riskScore: 0,
      signals: [],
    };
  }

  const signals: string[] = [];
  let riskScore = 0;
  let isObfuscated = false;
  let technique: string | undefined;
  let decodedUrl: string | undefined;

  // Check for excessive URL length
  if (url.length > 2000) {
    signals.push('excessive_url_length');
    riskScore += 3;
  }

  // Check for excessive query parameters
  const queryParams = url.split('?')[1]?.split('&') || [];
  if (queryParams.length > 20) {
    signals.push('excessive_parameters');
    riskScore += 2;
  }

  // Check for credential prefix attack (user@host)
  const credentialMatch = url.match(/https?:\/\/([^@]+)@([^\/]+)/);
  if (credentialMatch) {
    isObfuscated = true;
    technique = 'credential_prefix';
    decodedUrl = `https://${credentialMatch[2]}/`;
    riskScore = Math.max(riskScore, 9);
    signals.push('credential_prefix_attack');

    // CRITICAL: Check if credential prefix contains brand impersonation
    // This is a common phishing technique: fake-brand.com@evil.com
    const credentialPart = credentialMatch[1].toLowerCase();
    const brandCheck = checkBrandImpersonation(credentialPart);
    if (brandCheck.isLookalike) {
      riskScore = 10; // Maximum risk - credential prefix impersonating a brand
      signals.push('brand_in_credential_prefix');
    }
  }

  // Check for double encoding (%25 = %)
  if (/%25[0-9a-f]{2}/i.test(url)) {
    isObfuscated = true;
    technique = 'double_encoding';
    riskScore = Math.max(riskScore, 8);
    signals.push('double_encoding');
  }

  // Check for encoded critical characters in hostname
  // %2e = '.', %2f = '/'
  if (!isObfuscated) {
    const beforeQuery = url.split('?')[0];
    if (/%2[ef]/i.test(beforeQuery)) {
      isObfuscated = true;
      technique = 'percent_encoding';
      riskScore = Math.max(riskScore, 6);
      signals.push('encoded_hostname_characters');
    }
  }

  // Check for decimal IP address
  // e.g., http://2130706433/ = http://127.0.0.1/
  const decimalIpMatch = url.match(/https?:\/\/(\d{8,})(\/|$|\?)/);
  if (decimalIpMatch) {
    isObfuscated = true;
    technique = 'decimal_ip';
    riskScore = Math.max(riskScore, 8);
    signals.push('decimal_ip_address');
    // Decode decimal IP
    const decimal = parseInt(decimalIpMatch[1], 10);
    const ip = [
      (decimal >> 24) & 255,
      (decimal >> 16) & 255,
      (decimal >> 8) & 255,
      decimal & 255,
    ].join('.');
    decodedUrl = url.replace(decimalIpMatch[1], ip);
  }

  // Check for hex IP address
  if (/https?:\/\/0x[0-9a-f]+/i.test(url) || /https?:\/\/([0-9]+\.0x|0x[0-9a-f]+\.)/i.test(url)) {
    isObfuscated = true;
    technique = 'hex_ip';
    riskScore = Math.max(riskScore, 8);
    signals.push('hex_ip_address');
  }

  // Check for fullwidth unicode characters
  if (/[\uff01-\uff5e]/.test(url)) {
    isObfuscated = true;
    technique = 'unicode_normalization';
    riskScore = Math.max(riskScore, 7);
    signals.push('fullwidth_unicode');
  }

  // Check for URL shortener chains
  const shortenerCount = URL_SHORTENERS.filter(s => url.includes(s)).length;
  if (shortenerCount >= 2 || (shortenerCount === 1 && /url=/i.test(url))) {
    isObfuscated = true;
    technique = 'shortener_chain';
    riskScore = Math.max(riskScore, 5);
    signals.push('url_shortener_chain');
  }

  // Check for base64 encoded URLs in parameters
  const base64Match = url.match(/[?&](url|redirect|goto|link|next)=([A-Za-z0-9+/=]{20,})/);
  if (base64Match) {
    try {
      const decoded = Buffer.from(base64Match[2], 'base64').toString('utf-8');
      if (decoded.startsWith('http')) {
        isObfuscated = true;
        technique = 'base64_payload';
        decodedUrl = decoded;
        riskScore = Math.max(riskScore, 6);
        signals.push('base64_encoded_url');
      }
    } catch {
      // Not valid base64, ignore
    }
  }

  return {
    url,
    isObfuscated,
    technique,
    riskScore: Math.min(10, riskScore),
    signals,
    decodedUrl,
  };
}

// ============================================================================
// Redirect Chain Analysis
// ============================================================================

/**
 * Analyze redirect chain for suspicious patterns
 */
export function analyzeRedirectChain(urls: string[]): RedirectChainResult {
  if (!urls || urls.length === 0) {
    return {
      urls: [],
      chainLength: 0,
      isSuspicious: false,
      riskScore: 0,
      signals: [],
    };
  }

  if (urls.length === 1) {
    return {
      urls,
      chainLength: 1,
      isSuspicious: false,
      riskScore: 0,
      signals: [],
      finalDestination: urls[0],
    };
  }

  const signals: string[] = [];
  let riskScore = 0;
  let isSuspicious = false;

  // Long redirect chains are suspicious
  if (urls.length >= 4) {
    isSuspicious = true;
    // Base score of 5 for 4+ hops, plus 1 for each additional hop (max +5)
    riskScore += 5 + Math.min(5, urls.length - 4);
    signals.push('long_redirect_chain');
  }

  // Count shorteners
  const shortenerHops = urls.filter(url =>
    URL_SHORTENERS.some(s => url.includes(s))
  ).length;

  if (shortenerHops >= 2) {
    isSuspicious = true;
    riskScore += 5; // Increased from 3 - multiple shorteners are very suspicious
    signals.push('multiple_shorteners');
  }

  // Analyze domain changes
  const domains = urls.map(url => {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return '';
    }
  }).filter(Boolean);

  // TLD changes
  const tlds = domains.map(d => d.split('.').slice(-1)[0]);
  const uniqueTlds = new Set(tlds);
  if (uniqueTlds.size > 1) {
    const suspiciousTlds = [...uniqueTlds].filter(tld =>
      HIGH_RISK_TLDS.some(risk => risk.endsWith(tld))
    );
    if (suspiciousTlds.length > 0) {
      isSuspicious = true;
      riskScore += 3;
      signals.push('tld_change');
    }
  }

  // HTTPS to HTTP downgrade
  for (let i = 1; i < urls.length; i++) {
    if (urls[i - 1].startsWith('https://') && urls[i].startsWith('http://')) {
      isSuspicious = true;
      riskScore += 5;
      signals.push('https_downgrade');
      break;
    }
  }

  // Redirect to IP address
  const lastDomain = domains[domains.length - 1];
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lastDomain)) {
    isSuspicious = true;
    riskScore += 6;
    signals.push('redirect_to_ip');
  }

  // Check final destination TLD
  const finalUrl = urls[urls.length - 1];
  const finalTld = '.' + (lastDomain?.split('.').slice(-1)[0] || '');
  if (HIGH_RISK_TLDS.includes(finalTld)) {
    isSuspicious = true;
    riskScore += 4;
    signals.push('suspicious_final_tld');
  }

  return {
    urls,
    chainLength: urls.length,
    isSuspicious,
    riskScore: Math.min(10, riskScore),
    signals,
    finalDestination: finalUrl,
  };
}

// ============================================================================
// Comprehensive URL Intelligence
// ============================================================================

/**
 * Get comprehensive URL intelligence combining all analysis methods
 */
export async function getURLIntelligence(
  url: string,
  options: URLIntelligenceOptions = {}
): Promise<URLIntelligenceResult> {
  const signals: string[] = [];
  let overallRiskScore = 0;
  const breakdown: URLIntelligenceResult['breakdown'] = {};

  // Try to parse URL
  let hostname: string;
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname.toLowerCase();
  } catch {
    return {
      url,
      overallRiskScore: 5,
      verdict: 'suspicious',
      signals: ['invalid_url'],
      parseError: true,
      breakdown,
    };
  }

  let domainAge: DomainAgeResult | undefined;
  let lookalike: LookalikeResult | undefined;
  let obfuscation: ObfuscationResult | undefined;
  let redirectChain: RedirectChainResult | undefined;

  // Domain age analysis
  if (options.checkDomainAge && options.whoisData) {
    domainAge = analyzeDomainAge(hostname, options.whoisData);
    breakdown.domainAge = domainAge.riskScore;
    overallRiskScore += domainAge.riskScore * 0.4;
    signals.push(...domainAge.signals);
  }

  // Lookalike detection - high weight as this is a strong indicator
  if (options.checkLookalike !== false) {
    lookalike = detectLookalikeDomain(hostname);
    breakdown.lookalike = lookalike.riskScore;
    overallRiskScore += lookalike.riskScore * 0.7;
    signals.push(...lookalike.signals);
  }

  // Obfuscation detection - high weight as this is a strong indicator
  if (options.checkObfuscation !== false) {
    obfuscation = detectURLObfuscation(url);
    breakdown.obfuscation = obfuscation.riskScore;
    // Credential prefix with brand impersonation is critical - use 1.0 multiplier
    const obfuscationMultiplier = obfuscation.signals.includes('brand_in_credential_prefix') ? 1.0 : 0.6;
    overallRiskScore += obfuscation.riskScore * obfuscationMultiplier;
    signals.push(...obfuscation.signals);
  }

  // Redirect chain analysis
  if (options.checkRedirectChain && options.redirectChain) {
    redirectChain = analyzeRedirectChain(options.redirectChain);
    breakdown.redirectChain = redirectChain.riskScore;
    overallRiskScore += redirectChain.riskScore * 0.3;
    signals.push(...redirectChain.signals);
  }

  // Determine verdict
  const normalizedScore = Math.min(10, overallRiskScore);
  let verdict: 'safe' | 'suspicious' | 'malicious';
  if (normalizedScore >= 7) {
    verdict = 'malicious';
  } else if (normalizedScore >= 3) {
    verdict = 'suspicious';
  } else {
    verdict = 'safe';
  }

  return {
    url,
    overallRiskScore: normalizedScore,
    verdict,
    signals: [...new Set(signals)], // Deduplicate
    domainAge,
    lookalike,
    obfuscation,
    redirectChain,
    breakdown,
  };
}
