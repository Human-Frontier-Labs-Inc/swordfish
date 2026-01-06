/**
 * PhishTank Feed Integration
 * Fetches and parses the PhishTank verified phishing URL database
 * https://phishtank.org/
 */

export interface PhishTankEntry {
  phish_id: string;
  url: string;
  phish_detail_url: string;
  submission_time: string;
  verified: 'yes' | 'no';
  verified_time: string | null;
  online: 'yes' | 'no';
  target: string;
}

// PhishTank API requires an API key for full access
// Free tier has rate limits
const PHISHTANK_API_KEY = process.env.PHISHTANK_API_KEY || '';
const PHISHTANK_DATA_URL = 'http://data.phishtank.com/data/online-valid.json';

// Fallback: Sample known phishing patterns for development/testing
// These patterns detect brand impersonation - domains that look like legitimate brands but aren't
const KNOWN_PHISHING_PATTERNS = [
  // Common phishing domain patterns - impersonation with hyphens or suspicious TLDs
  /paypal-.*\.(com|net|org|xyz|tk|ml)/i,
  /microsoft-.*\.(com|net|org|xyz|tk|ml)/i,
  /apple-.*\.(com|net|org|xyz|tk|ml)/i,
  /google-.*\.(com|net|org|xyz|tk|ml)/i,
  /amazon-.*\.(com|net|org|xyz|tk|ml)/i,
  /netflix-.*\.(com|net|org|xyz|tk|ml)/i,
  /facebook-.*\.(com|net|org|xyz|tk|ml)/i,
  // Credential harvesting paths combined with brand names in non-official domains
  /bank.*login/i,
  /secure.*update/i,
  /account.*verify/i,
  /signin.*confirm/i,
];

// Track if we've already logged the sample data warning
let sampleDataWarningLogged = false;

// Extended sample phishing URLs covering common brand impersonation attacks
// Used when PhishTank API is unavailable (registration closed as of 2024)
const SAMPLE_PHISHING_URLS: PhishTankEntry[] = [
  // PayPal variants
  { phish_id: 'pat-1', url: 'http://paypal-secure-login.malicious.com/signin', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'PayPal' },
  { phish_id: 'pat-2', url: 'http://paypa1-verify.suspicious.net/update', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'PayPal' },
  { phish_id: 'pat-3', url: 'http://secure-paypal.account-verify.com/login', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'PayPal' },
  // Microsoft variants
  { phish_id: 'pat-4', url: 'http://microsoft-account-verify.fake.xyz/login', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Microsoft' },
  { phish_id: 'pat-5', url: 'http://micros0ft-login.secure-auth.xyz/office365', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Microsoft' },
  { phish_id: 'pat-6', url: 'http://office365-password-reset.com/verify', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Microsoft' },
  { phish_id: 'pat-7', url: 'http://sharepoint-document.secure-view.net/download', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Microsoft' },
  // Google variants
  { phish_id: 'pat-8', url: 'http://google-account-verify.suspicious.com/signin', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Google' },
  { phish_id: 'pat-9', url: 'http://g00gle-security.alert-center.xyz/verify', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Google' },
  { phish_id: 'pat-10', url: 'http://drive-google.share-document.net/view', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Google' },
  // Apple variants
  { phish_id: 'pat-11', url: 'http://apple-id-verify.secure-login.xyz/icloud', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Apple' },
  { phish_id: 'pat-12', url: 'http://app1e-support.account-locked.com/unlock', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Apple' },
  // Amazon variants
  { phish_id: 'pat-13', url: 'http://amazon-prime-verify.suspicious.net/account', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Amazon' },
  { phish_id: 'pat-14', url: 'http://amaz0n-order.delivery-update.xyz/track', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Amazon' },
  // Banking variants
  { phish_id: 'pat-15', url: 'http://chase-secure-login.account-verify.com/signin', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Chase Bank' },
  { phish_id: 'pat-16', url: 'http://wellsfargo-alert.security-center.xyz/verify', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Wells Fargo' },
  { phish_id: 'pat-17', url: 'http://bankofamerica.secure-update.net/login', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Bank of America' },
  // Netflix variants
  { phish_id: 'pat-18', url: 'http://netflix-payment-update.suspicious.com/billing', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Netflix' },
  // Shipping variants
  { phish_id: 'pat-19', url: 'http://dhl-delivery.track-package.xyz/status', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'DHL' },
  { phish_id: 'pat-20', url: 'http://usps-redelivery.schedule-now.net/confirm', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'USPS' },
  { phish_id: 'pat-21', url: 'http://fedex-customs.payment-required.com/pay', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'FedEx' },
  // Social media variants
  { phish_id: 'pat-22', url: 'http://facebook-security.verify-identity.xyz/confirm', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Facebook' },
  { phish_id: 'pat-23', url: 'http://instagram-copyright.appeal-form.net/submit', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'Instagram' },
  { phish_id: 'pat-24', url: 'http://linkedin-job.application-review.com/apply', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'LinkedIn' },
  // Docusign variants (common in BEC)
  { phish_id: 'pat-25', url: 'http://docusign-document.review-sign.xyz/view', phish_detail_url: '', submission_time: new Date().toISOString(), verified: 'yes', verified_time: new Date().toISOString(), online: 'yes', target: 'DocuSign' },
];

/**
 * Fetch the PhishTank feed
 */
export async function fetchPhishTankFeed(): Promise<PhishTankEntry[]> {
  try {
    // If we have an API key, fetch from the real API
    if (PHISHTANK_API_KEY) {
      const response = await fetch(PHISHTANK_DATA_URL, {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Swordfish-Email-Security/1.0',
        },
      });

      if (!response.ok) {
        console.warn(`PhishTank API returned ${response.status}`);
        return SAMPLE_PHISHING_URLS;
      }

      const data = await response.json() as PhishTankEntry[];

      // Filter to only verified and online entries
      return data.filter(entry =>
        entry.verified === 'yes' && entry.online === 'yes'
      );
    }

    // No API key - use pattern-based detection (PhishTank registration closed)
    // Only log once per server instance to reduce noise
    if (!sampleDataWarningLogged) {
      console.log('[PhishTank] Using pattern-based detection (API registration closed). URLhaus and OpenPhish feeds active.');
      sampleDataWarningLogged = true;
    }
    return SAMPLE_PHISHING_URLS;
  } catch (error) {
    console.error('[PhishTank] Feed fetch error:', error);
    return SAMPLE_PHISHING_URLS;
  }
}

/**
 * Check a URL against PhishTank patterns
 * Used for real-time checking without full feed
 */
export function checkPhishTankUrl(url: string): {
  isPhishing: boolean;
  matchedPattern?: string;
  confidence: number;
} {
  const normalizedUrl = url.toLowerCase();

  // Check against known patterns
  for (const pattern of KNOWN_PHISHING_PATTERNS) {
    if (pattern.test(normalizedUrl)) {
      return {
        isPhishing: true,
        matchedPattern: pattern.toString(),
        confidence: 0.7, // Pattern match is less certain than feed match
      };
    }
  }

  // Check for homoglyph attacks (look-alike domains)
  const homoglyphResult = checkHomoglyphAttack(normalizedUrl);
  if (homoglyphResult.isAttack) {
    return {
      isPhishing: true,
      matchedPattern: `Homoglyph attack impersonating ${homoglyphResult.target}`,
      confidence: 0.85,
    };
  }

  return {
    isPhishing: false,
    confidence: 0.5,
  };
}

/**
 * Check for homoglyph/look-alike domain attacks
 */
function checkHomoglyphAttack(url: string): {
  isAttack: boolean;
  target?: string;
} {
  // Common substitutions used in homoglyph attacks
  const homoglyphs: Record<string, string[]> = {
    'a': ['а', 'ą', 'ä', 'å', 'à', 'á', 'ã', '4', '@'],
    'e': ['е', 'ę', 'ë', 'é', 'è', '3'],
    'i': ['і', 'ı', 'ì', 'í', 'ï', '1', 'l', '!'],
    'o': ['о', 'ö', 'ó', 'ò', 'ô', '0'],
    'c': ['с', 'ç'],
    'p': ['р'],
    'x': ['х'],
    'y': ['у', 'ý'],
    'n': ['п'],
    's': ['ѕ', '$', '5'],
    'l': ['1', 'I', '|'],
    'g': ['9', 'q'],
    't': ['7', '+'],
    'b': ['8'],
  };

  // Protected brands to check
  const protectedBrands = [
    { name: 'paypal', domain: 'paypal.com' },
    { name: 'microsoft', domain: 'microsoft.com' },
    { name: 'google', domain: 'google.com' },
    { name: 'apple', domain: 'apple.com' },
    { name: 'amazon', domain: 'amazon.com' },
    { name: 'facebook', domain: 'facebook.com' },
    { name: 'netflix', domain: 'netflix.com' },
    { name: 'linkedin', domain: 'linkedin.com' },
    { name: 'dropbox', domain: 'dropbox.com' },
    { name: 'chase', domain: 'chase.com' },
    { name: 'wellsfargo', domain: 'wellsfargo.com' },
    { name: 'bankofamerica', domain: 'bankofamerica.com' },
  ];

  try {
    const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
    const domain = parsed.hostname.toLowerCase();

    for (const brand of protectedBrands) {
      // Skip if it's the actual domain
      if (domain === brand.domain || domain.endsWith(`.${brand.domain}`)) {
        continue;
      }

      // Check if domain looks like the brand
      const brandChars = brand.name.split('');
      let similarity = 0;
      let domainWithoutTld = domain.split('.')[0];

      // Simple Levenshtein-like check
      for (let i = 0; i < Math.min(brandChars.length, domainWithoutTld.length); i++) {
        if (brandChars[i] === domainWithoutTld[i]) {
          similarity++;
        } else if (homoglyphs[brandChars[i]]?.includes(domainWithoutTld[i])) {
          similarity += 0.9; // Near match with homoglyph
        }
      }

      const similarityRatio = similarity / brand.name.length;
      if (similarityRatio > 0.7 && domain !== brand.domain) {
        return { isAttack: true, target: brand.name };
      }
    }
  } catch {
    // Invalid URL, not a homoglyph attack
  }

  return { isAttack: false };
}
