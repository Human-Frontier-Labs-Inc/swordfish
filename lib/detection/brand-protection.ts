/**
 * Brand Protection Module - Phase 1: Expanded Coverage
 *
 * Comprehensive brand impersonation detection including:
 * - 65+ high-value brand domains (expanded from 15)
 * - Enhanced homoglyph detection with Unicode normalization
 * - Cousin domain detection with common patterns
 * - Typosquatting pattern recognition
 *
 * Expected Impact: +2 points to detection score (reduces brand-based phishing false negatives)
 */

export interface BrandMatch {
  brand: string;
  domain: string;
  category: BrandCategory;
  attackType: 'homoglyph' | 'cousin' | 'typosquat' | 'exact';
  confidence: number; // 0-1
  detail: string;
}

export type BrandCategory =
  | 'financial'
  | 'tech'
  | 'ecommerce'
  | 'social'
  | 'enterprise'
  | 'shipping'
  | 'government'
  | 'healthcare'
  | 'telecom'
  | 'media';

interface BrandEntry {
  domain: string;
  brand: string;
  category: BrandCategory;
  aliases?: string[]; // Alternative spellings/names
}

/**
 * Expanded brand database - 65+ high-value targets
 * Organized by category for better management
 */
export const PROTECTED_BRANDS: BrandEntry[] = [
  // Financial Services (15)
  { domain: 'paypal.com', brand: 'PayPal', category: 'financial' },
  { domain: 'bankofamerica.com', brand: 'Bank of America', category: 'financial', aliases: ['bofa', 'boa'] },
  { domain: 'chase.com', brand: 'Chase', category: 'financial', aliases: ['jpmorgan'] },
  { domain: 'wellsfargo.com', brand: 'Wells Fargo', category: 'financial' },
  { domain: 'capitalone.com', brand: 'Capital One', category: 'financial' },
  { domain: 'citi.com', brand: 'Citibank', category: 'financial', aliases: ['citibank'] },
  { domain: 'americanexpress.com', brand: 'American Express', category: 'financial', aliases: ['amex'] },
  { domain: 'discover.com', brand: 'Discover', category: 'financial' },
  { domain: 'fidelity.com', brand: 'Fidelity', category: 'financial' },
  { domain: 'schwab.com', brand: 'Charles Schwab', category: 'financial' },
  { domain: 'vanguard.com', brand: 'Vanguard', category: 'financial' },
  { domain: 'tdameritrade.com', brand: 'TD Ameritrade', category: 'financial' },
  { domain: 'usbank.com', brand: 'US Bank', category: 'financial' },
  { domain: 'pnc.com', brand: 'PNC Bank', category: 'financial' },
  { domain: 'stripe.com', brand: 'Stripe', category: 'financial' },

  // Tech Giants (12)
  { domain: 'microsoft.com', brand: 'Microsoft', category: 'tech' },
  { domain: 'apple.com', brand: 'Apple', category: 'tech', aliases: ['icloud'] },
  { domain: 'google.com', brand: 'Google', category: 'tech', aliases: ['gmail', 'youtube'] },
  { domain: 'amazon.com', brand: 'Amazon', category: 'tech', aliases: ['aws'] },
  { domain: 'meta.com', brand: 'Meta', category: 'tech', aliases: ['facebook'] },
  { domain: 'netflix.com', brand: 'Netflix', category: 'tech' },
  { domain: 'adobe.com', brand: 'Adobe', category: 'tech' },
  { domain: 'oracle.com', brand: 'Oracle', category: 'tech' },
  { domain: 'salesforce.com', brand: 'Salesforce', category: 'tech' },
  { domain: 'dropbox.com', brand: 'Dropbox', category: 'tech' },
  { domain: 'zoom.us', brand: 'Zoom', category: 'tech' },
  { domain: 'slack.com', brand: 'Slack', category: 'tech' },

  // E-commerce (8)
  { domain: 'ebay.com', brand: 'eBay', category: 'ecommerce' },
  { domain: 'walmart.com', brand: 'Walmart', category: 'ecommerce' },
  { domain: 'target.com', brand: 'Target', category: 'ecommerce' },
  { domain: 'bestbuy.com', brand: 'Best Buy', category: 'ecommerce' },
  { domain: 'costco.com', brand: 'Costco', category: 'ecommerce' },
  { domain: 'homedepot.com', brand: 'Home Depot', category: 'ecommerce' },
  { domain: 'etsy.com', brand: 'Etsy', category: 'ecommerce' },
  { domain: 'aliexpress.com', brand: 'AliExpress', category: 'ecommerce' },

  // Social Media (6)
  { domain: 'linkedin.com', brand: 'LinkedIn', category: 'social' },
  { domain: 'twitter.com', brand: 'Twitter', category: 'social', aliases: ['x'] },
  { domain: 'instagram.com', brand: 'Instagram', category: 'social' },
  { domain: 'tiktok.com', brand: 'TikTok', category: 'social' },
  { domain: 'pinterest.com', brand: 'Pinterest', category: 'social' },
  { domain: 'reddit.com', brand: 'Reddit', category: 'social' },

  // Enterprise Software (8)
  { domain: 'docusign.com', brand: 'DocuSign', category: 'enterprise' },
  { domain: 'servicenow.com', brand: 'ServiceNow', category: 'enterprise' },
  { domain: 'workday.com', brand: 'Workday', category: 'enterprise' },
  { domain: 'atlassian.com', brand: 'Atlassian', category: 'enterprise', aliases: ['jira', 'confluence'] },
  { domain: 'hubspot.com', brand: 'HubSpot', category: 'enterprise' },
  { domain: 'zendesk.com', brand: 'Zendesk', category: 'enterprise' },
  { domain: 'intuit.com', brand: 'Intuit', category: 'enterprise', aliases: ['quickbooks', 'turbotax'] },
  { domain: 'github.com', brand: 'GitHub', category: 'enterprise' },

  // Shipping & Logistics (6)
  { domain: 'fedex.com', brand: 'FedEx', category: 'shipping' },
  { domain: 'ups.com', brand: 'UPS', category: 'shipping' },
  { domain: 'usps.com', brand: 'USPS', category: 'shipping' },
  { domain: 'dhl.com', brand: 'DHL', category: 'shipping' },
  { domain: 'amazon.com', brand: 'Amazon Logistics', category: 'shipping' },
  { domain: 'ontrac.com', brand: 'OnTrac', category: 'shipping' },

  // Telecom (5)
  { domain: 'att.com', brand: 'AT&T', category: 'telecom' },
  { domain: 'verizon.com', brand: 'Verizon', category: 'telecom' },
  { domain: 't-mobile.com', brand: 'T-Mobile', category: 'telecom' },
  { domain: 'xfinity.com', brand: 'Xfinity', category: 'telecom', aliases: ['comcast'] },
  { domain: 'spectrum.com', brand: 'Spectrum', category: 'telecom' },

  // Media & Entertainment (5)
  { domain: 'spotify.com', brand: 'Spotify', category: 'media' },
  { domain: 'hulu.com', brand: 'Hulu', category: 'media' },
  { domain: 'disneyplus.com', brand: 'Disney+', category: 'media', aliases: ['disney'] },
  { domain: 'hbomax.com', brand: 'HBO Max', category: 'media', aliases: ['hbo'] },
  { domain: 'peacocktv.com', brand: 'Peacock', category: 'media' },
];

/**
 * Enhanced homoglyph character mappings
 * Includes Unicode confusables and common substitutions
 */
export const HOMOGLYPHS: Record<string, string[]> = {
  'a': ['а', 'ɑ', 'α', '@', 'ａ', 'ä', 'à', 'á', 'â', 'ã'],
  'b': ['ƅ', 'Ь', 'ｂ', 'ḃ'],
  'c': ['с', 'ϲ', '¢', 'ｃ', 'ç'],
  'd': ['ԁ', 'ɗ', 'ｄ', 'ḋ'],
  'e': ['е', 'ё', '℮', 'ｅ', 'é', 'è', 'ê', 'ë'],
  'f': ['ｆ', 'ƒ'],
  'g': ['ɡ', 'ց', 'ｇ', 'ġ'],
  'h': ['һ', 'հ', 'ｈ', 'ḣ'],
  'i': ['і', 'ı', '1', 'l', '|', 'ｉ', 'í', 'ì', 'î', 'ï'],
  'j': ['ј', 'ʝ', 'ｊ'],
  'k': ['κ', 'ķ', 'ｋ', 'ḱ'],
  'l': ['ӏ', 'ɭ', '1', 'i', '|', 'ｌ', 'ĺ'],
  'm': ['м', 'ṃ', 'ｍ', 'ṁ'],
  'n': ['ո', 'ņ', 'ｎ', 'ń', 'ñ'],
  'o': ['о', 'ο', '0', 'ө', 'ｏ', 'ó', 'ò', 'ô', 'ö', 'õ'],
  'p': ['р', 'ρ', 'ｐ'],
  'q': ['ԛ', 'գ', 'ｑ'],
  'r': ['г', 'ɾ', 'ｒ', 'ŕ'],
  's': ['ѕ', 'ꜱ', '$', 'ｓ', 'ś', 'š'],
  't': ['т', 'ţ', 'ｔ', 'ṫ'],
  'u': ['υ', 'ս', 'ｕ', 'ú', 'ù', 'û', 'ü'],
  'v': ['ѵ', 'ν', 'ｖ'],
  'w': ['ѡ', 'ω', 'ｗ', 'ẃ'],
  'x': ['х', 'χ', 'ｘ'],
  'y': ['у', 'ү', 'ｙ', 'ý', 'ÿ'],
  'z': ['ᴢ', 'ʐ', 'ｚ', 'ż', 'ź'],
  '0': ['о', 'ο', 'O', '０'],
  '1': ['l', 'i', 'I', '|', '１'],
  '2': ['２', 'ƨ'],
  '3': ['３', 'з'],
  '4': ['４'],
  '5': ['５', 'ƽ'],
  '6': ['６', 'б'],
  '7': ['７'],
  '8': ['８'],
  '9': ['９', 'g'],
};

/**
 * Common typosquatting patterns
 */
const TYPOSQUAT_PATTERNS = [
  // Character omission (missing letter)
  (brand: string) => brand.split('').map((_, i) => brand.slice(0, i) + brand.slice(i + 1)),
  // Character duplication
  (brand: string) => brand.split('').map((c, i) => brand.slice(0, i) + c + brand.slice(i)),
  // Adjacent key substitution (QWERTY keyboard)
  (brand: string) => {
    const adjacent: Record<string, string[]> = {
      'q': ['w', 'a'], 'w': ['q', 'e', 's'], 'e': ['w', 'r', 'd'], 'r': ['e', 't', 'f'],
      't': ['r', 'y', 'g'], 'y': ['t', 'u', 'h'], 'u': ['y', 'i', 'j'], 'i': ['u', 'o', 'k'],
      'o': ['i', 'p', 'l'], 'p': ['o', 'l'], 'a': ['q', 's', 'z'], 's': ['a', 'w', 'd', 'x'],
      'd': ['s', 'e', 'f', 'c'], 'f': ['d', 'r', 'g', 'v'], 'g': ['f', 't', 'h', 'b'],
      'h': ['g', 'y', 'j', 'n'], 'j': ['h', 'u', 'k', 'm'], 'k': ['j', 'i', 'l'],
      'l': ['k', 'o', 'p'], 'z': ['a', 's', 'x'], 'x': ['z', 's', 'd', 'c'],
      'c': ['x', 'd', 'f', 'v'], 'v': ['c', 'f', 'g', 'b'], 'b': ['v', 'g', 'h', 'n'],
      'n': ['b', 'h', 'j', 'm'], 'm': ['n', 'j', 'k'],
    };
    const results: string[] = [];
    for (let i = 0; i < brand.length; i++) {
      const char = brand[i].toLowerCase();
      if (adjacent[char]) {
        for (const adj of adjacent[char]) {
          results.push(brand.slice(0, i) + adj + brand.slice(i + 1));
        }
      }
    }
    return results;
  },
  // Character transposition (swapped adjacent letters)
  (brand: string) => {
    const results: string[] = [];
    for (let i = 0; i < brand.length - 1; i++) {
      results.push(brand.slice(0, i) + brand[i + 1] + brand[i] + brand.slice(i + 2));
    }
    return results;
  },
];

/**
 * Common cousin domain suffixes/prefixes
 */
const COUSIN_PATTERNS = [
  // Suffixes
  '-secure', '-login', '-verify', '-account', '-support', '-help',
  '-service', '-online', '-portal', '-access', '-update', '-alert',
  '-confirm', '-billing', '-payment', '-security', '-auth',
  // Prefixes
  'secure-', 'login-', 'my-', 'account-', 'support-', 'help-',
  'service-', 'online-', 'portal-', 'mail-', 'web-', 'app-',
  // Common TLD variations
  '.net', '.org', '.co', '.io', '.info', '.biz', '.online', '.site',
];

/**
 * Normalize a string for comparison (removes accents, converts to lowercase)
 */
function normalizeString(str: string): string {
  return str
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, ''); // Remove diacritical marks
}

/**
 * Check if a character is a homoglyph of another
 */
function isHomoglyph(testChar: string, targetChar: string): boolean {
  const normalizedTarget = targetChar.toLowerCase();
  const normalizedTest = testChar.toLowerCase();

  if (normalizedTest === normalizedTarget) return true;

  const homoglyphsForTarget = HOMOGLYPHS[normalizedTarget] || [];
  return homoglyphsForTarget.includes(testChar) || homoglyphsForTarget.includes(normalizedTest);
}

/**
 * Calculate the homoglyph similarity between two strings
 * Returns a score from 0-1 (1 = perfect homoglyph match)
 */
function homoglyphSimilarity(test: string, target: string): number {
  if (test.length !== target.length) return 0;

  let matches = 0;
  let homoglyphMatches = 0;

  for (let i = 0; i < test.length; i++) {
    if (test[i].toLowerCase() === target[i].toLowerCase()) {
      matches++;
    } else if (isHomoglyph(test[i], target[i])) {
      homoglyphMatches++;
    }
  }

  // Must have at least one homoglyph substitution to be considered an attack
  if (homoglyphMatches === 0) return 0;

  // All characters must either match exactly or be homoglyphs
  if (matches + homoglyphMatches === test.length) {
    return 0.9 + (homoglyphMatches / test.length) * 0.1; // Score 0.9-1.0
  }

  return 0;
}

/**
 * Check if domain is a typosquat of a brand
 */
function isTyposquat(testDomain: string, brandBase: string): { match: boolean; pattern?: string } {
  const testBase = testDomain.split('.')[0].toLowerCase();
  const targetBase = brandBase.toLowerCase();

  if (testBase === targetBase) return { match: false };

  for (const patternFn of TYPOSQUAT_PATTERNS) {
    const typos = patternFn(targetBase);
    if (typos.includes(testBase)) {
      return { match: true, pattern: 'typosquatting pattern detected' };
    }
  }

  return { match: false };
}

/**
 * Check if domain is a cousin domain of a brand
 * Minimum brand length of 3 characters to avoid false positives from short aliases
 */
function isCousinDomain(testDomain: string, brandBase: string): { match: boolean; pattern?: string } {
  const testLower = testDomain.toLowerCase();
  const brandLower = brandBase.toLowerCase();

  // Minimum brand name length to prevent false matches on short aliases (e.g., 'x' for Twitter)
  if (brandLower.length < 3) return { match: false };

  // Check if test domain contains brand name with additions
  if (!testLower.includes(brandLower)) return { match: false };
  if (testLower === brandLower) return { match: false };

  // Extract the base domain (before the TLD)
  const testBase = testLower.split('.')[0];

  for (const pattern of COUSIN_PATTERNS) {
    if (pattern.startsWith('-') || pattern.startsWith('.')) {
      // Suffix pattern
      if (testBase.includes(brandLower + pattern.replace('.', '')) || testBase.endsWith(pattern.replace('.', ''))) {
        return { match: true, pattern: `cousin domain with suffix "${pattern}"` };
      }
    } else if (pattern.endsWith('-')) {
      // Prefix pattern
      if (testBase.includes(pattern + brandLower)) {
        return { match: true, pattern: `cousin domain with prefix "${pattern}"` };
      }
    }
  }

  // Generic cousin domain (brand name + other text)
  // Must have the brand as a distinct segment (word boundary check)
  if (testBase !== brandLower && testBase.includes(brandLower)) {
    // Check if brand appears at word boundary (start, after hyphen, or end)
    const brandIndex = testBase.indexOf(brandLower);
    const charBefore = brandIndex > 0 ? testBase[brandIndex - 1] : '-';
    const charAfter = brandIndex + brandLower.length < testBase.length ? testBase[brandIndex + brandLower.length] : '-';

    // Brand should be at a word boundary (start of domain or after hyphen)
    if (charBefore === '-' || brandIndex === 0) {
      return { match: true, pattern: 'cousin domain containing brand name' };
    }
  }

  return { match: false };
}

/**
 * Detect brand impersonation in a domain
 * Returns all matching brands with attack types
 */
export function detectBrandImpersonation(domain: string): BrandMatch[] {
  const matches: BrandMatch[] = [];
  const testDomain = domain.toLowerCase();
  const testBase = testDomain.split('.')[0];

  for (const brand of PROTECTED_BRANDS) {
    const brandBase = brand.domain.split('.')[0];
    const allNames = [brandBase, ...(brand.aliases || [])];

    for (const name of allNames) {
      // 1. Check for homoglyph attack
      const similarity = homoglyphSimilarity(testBase, name);
      if (similarity > 0.85) {
        matches.push({
          brand: brand.brand,
          domain: brand.domain,
          category: brand.category,
          attackType: 'homoglyph',
          confidence: similarity,
          detail: `Domain "${domain}" uses homoglyph characters to impersonate ${brand.brand}`,
        });
        continue;
      }

      // 2. Check for typosquatting
      const typosquat = isTyposquat(testDomain, name);
      if (typosquat.match) {
        matches.push({
          brand: brand.brand,
          domain: brand.domain,
          category: brand.category,
          attackType: 'typosquat',
          confidence: 0.85,
          detail: `Domain "${domain}" appears to be a typosquat of ${brand.brand} (${typosquat.pattern})`,
        });
        continue;
      }

      // 3. Check for cousin domain
      const cousin = isCousinDomain(testDomain, name);
      if (cousin.match) {
        matches.push({
          brand: brand.brand,
          domain: brand.domain,
          category: brand.category,
          attackType: 'cousin',
          confidence: 0.75,
          detail: `Domain "${domain}" is a ${cousin.pattern} of ${brand.brand}`,
        });
        continue;
      }
    }
  }

  // Deduplicate by brand (keep highest confidence)
  const deduped = new Map<string, BrandMatch>();
  for (const match of matches) {
    const existing = deduped.get(match.brand);
    if (!existing || match.confidence > existing.confidence) {
      deduped.set(match.brand, match);
    }
  }

  // Sort by confidence (highest first), then by brand name length (longer = more specific)
  return Array.from(deduped.values()).sort((a, b) => {
    if (b.confidence !== a.confidence) {
      return b.confidence - a.confidence;
    }
    // For equal confidence, prefer longer brand names (more specific matches)
    const aBase = a.domain.split('.')[0].length;
    const bBase = b.domain.split('.')[0].length;
    return bBase - aBase;
  });
}

/**
 * Check if a display name impersonates a brand
 */
export function detectDisplayNameBrandSpoof(
  displayName: string,
  senderDomain: string
): BrandMatch | null {
  const nameLower = displayName.toLowerCase();
  const domainLower = senderDomain.toLowerCase();

  for (const brand of PROTECTED_BRANDS) {
    const brandBase = brand.domain.split('.')[0];
    const allNames = [brandBase, brand.brand.toLowerCase(), ...(brand.aliases || [])];

    for (const name of allNames) {
      // Check if display name mentions brand but email is from different domain
      if (nameLower.includes(name) && !domainLower.includes(brandBase)) {
        return {
          brand: brand.brand,
          domain: brand.domain,
          category: brand.category,
          attackType: 'exact',
          confidence: 0.8,
          detail: `Display name "${displayName}" impersonates ${brand.brand} but sent from ${senderDomain}`,
        };
      }
    }
  }

  return null;
}

/**
 * Get all protected brand domains (for external use)
 */
export function getProtectedBrandDomains(): string[] {
  return PROTECTED_BRANDS.map(b => b.domain);
}

/**
 * Check if a domain exactly matches a protected brand
 */
export function isProtectedBrand(domain: string): boolean {
  const domainLower = domain.toLowerCase();
  return PROTECTED_BRANDS.some(b =>
    domainLower === b.domain || domainLower.endsWith(`.${b.domain}`)
  );
}
