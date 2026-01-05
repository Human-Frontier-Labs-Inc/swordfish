/**
 * OpenPhish Feed Integration
 * Fetches phishing URLs from the OpenPhish community feed
 * https://openphish.com/
 */

// OpenPhish provides a free community feed
const OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt';

// Sample phishing URLs for development/fallback
const SAMPLE_OPENPHISH_URLS = [
  'http://fake-bank-login.malicious.com/signin',
  'http://paypa1-verify.suspicious.net/update',
  'http://amaz0n-security.phish.xyz/account',
  'http://micros0ft-login.fake.org/office365',
  'http://app1e-id-verify.scam.co/icloud',
];

/**
 * Fetch the OpenPhish feed
 */
export async function fetchOpenPhishFeed(): Promise<string[]> {
  try {
    const response = await fetch(OPENPHISH_FEED_URL, {
      headers: {
        'User-Agent': 'Swordfish-Email-Security/1.0',
      },
    });

    if (!response.ok) {
      console.warn(`OpenPhish API returned ${response.status}`);
      return SAMPLE_OPENPHISH_URLS;
    }

    const text = await response.text();

    // OpenPhish returns one URL per line
    const urls = text
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && line.startsWith('http'));

    if (urls.length === 0) {
      return SAMPLE_OPENPHISH_URLS;
    }

    return urls;
  } catch (error) {
    console.error('[OpenPhish] Feed fetch error:', error);
    return SAMPLE_OPENPHISH_URLS;
  }
}

/**
 * Check a URL against OpenPhish patterns
 * Heuristic check when feed is not available
 */
export function checkOpenPhishUrl(url: string): {
  isPhishing: boolean;
  indicators: string[];
  confidence: number;
} {
  const normalizedUrl = url.toLowerCase();
  const indicators: string[] = [];

  try {
    const parsed = new URL(normalizedUrl.startsWith('http') ? normalizedUrl : `https://${normalizedUrl}`);
    const domain = parsed.hostname;
    const path = parsed.pathname;

    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link'];
    if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
      indicators.push('suspicious_tld');
    }

    // Check for credential harvesting paths
    const credentialPaths = ['/login', '/signin', '/verify', '/update', '/secure', '/account', '/password'];
    if (credentialPaths.some(p => path.includes(p))) {
      indicators.push('credential_harvesting_path');
    }

    // Check for brand impersonation in subdomain
    const brands = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'facebook', 'netflix', 'bank'];
    for (const brand of brands) {
      if (domain.includes(brand) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`.${brand}.com`)) {
        indicators.push(`brand_impersonation:${brand}`);
      }
    }

    // Check for number substitutions (l33t speak)
    const leetPatterns = [
      { original: 'o', replacement: '0' },
      { original: 'i', replacement: '1' },
      { original: 'e', replacement: '3' },
      { original: 'a', replacement: '4' },
      { original: 's', replacement: '5' },
    ];

    for (const { original, replacement } of leetPatterns) {
      for (const brand of brands) {
        const leetBrand = brand.replace(new RegExp(original, 'g'), replacement);
        if (domain.includes(leetBrand)) {
          indicators.push(`leet_substitution:${brand}`);
        }
      }
    }

    // Check for excessive subdomains (often used in phishing)
    const subdomainCount = domain.split('.').length - 2; // Exclude main domain and TLD
    if (subdomainCount > 2) {
      indicators.push('excessive_subdomains');
    }

    // Check for IP address in URL
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
      indicators.push('ip_based_url');
    }

    // Check for unusual port
    if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
      indicators.push('unusual_port');
    }

    // Check for data URI or javascript in URL
    if (normalizedUrl.includes('data:') || normalizedUrl.includes('javascript:')) {
      indicators.push('dangerous_protocol');
    }

    // Calculate confidence based on indicators
    const isPhishing = indicators.length >= 2 ||
      indicators.some(i => i.startsWith('brand_impersonation') || i === 'dangerous_protocol');

    let confidence = 0.3;
    if (indicators.includes('dangerous_protocol')) confidence = 0.95;
    else if (indicators.some(i => i.startsWith('brand_impersonation'))) confidence = 0.8;
    else if (indicators.length >= 3) confidence = 0.75;
    else if (indicators.length >= 2) confidence = 0.6;
    else if (indicators.length === 1) confidence = 0.4;

    return {
      isPhishing,
      indicators,
      confidence,
    };
  } catch {
    return {
      isPhishing: false,
      indicators: ['invalid_url'],
      confidence: 0.3,
    };
  }
}
