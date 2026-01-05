/**
 * URLhaus Feed Integration
 * Fetches and parses the abuse.ch URLhaus malware URL database
 * https://urlhaus.abuse.ch/
 */

export interface URLhausEntry {
  id: string;
  dateadded: string;
  url: string;
  url_status: 'online' | 'offline';
  threat: string;
  tags: string[];
  urlhaus_link: string;
  reporter: string;
}

// URLhaus provides free feeds
const URLHAUS_CSV_URL = 'https://urlhaus.abuse.ch/downloads/csv_online/';
const URLHAUS_JSON_URL = 'https://urlhaus.abuse.ch/downloads/json_online/';

// Sample malware URLs for development
const SAMPLE_MALWARE_URLS: URLhausEntry[] = [
  {
    id: 'sample-1',
    dateadded: new Date().toISOString(),
    url: 'http://malware-distribution.evil.com/payload.exe',
    url_status: 'online',
    threat: 'malware_download',
    tags: ['exe', 'Trojan'],
    urlhaus_link: 'https://urlhaus.abuse.ch/url/sample-1/',
    reporter: 'sample',
  },
  {
    id: 'sample-2',
    dateadded: new Date().toISOString(),
    url: 'http://ransomware-c2.bad.xyz/gate.php',
    url_status: 'online',
    threat: 'malware_download',
    tags: ['Ransomware', 'C2'],
    urlhaus_link: 'https://urlhaus.abuse.ch/url/sample-2/',
    reporter: 'sample',
  },
];

/**
 * Fetch the URLhaus feed
 */
export async function fetchURLhausFeed(): Promise<URLhausEntry[]> {
  try {
    const response = await fetch(URLHAUS_JSON_URL, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Swordfish-Email-Security/1.0',
      },
    });

    if (!response.ok) {
      console.warn(`URLhaus API returned ${response.status}`);
      return SAMPLE_MALWARE_URLS;
    }

    const data = await response.json();

    // URLhaus returns { query_status: "ok", urls: [...] }
    if (data.query_status === 'ok' && Array.isArray(data.urls)) {
      return data.urls.map((entry: {
        id: string;
        dateadded: string;
        url: string;
        url_status: string;
        threat: string;
        tags: string;
        urlhaus_reference: string;
        reporter: string;
      }) => ({
        id: entry.id,
        dateadded: entry.dateadded,
        url: entry.url,
        url_status: entry.url_status as 'online' | 'offline',
        threat: entry.threat,
        tags: entry.tags ? entry.tags.split(',').map((t: string) => t.trim()) : [],
        urlhaus_link: entry.urlhaus_reference,
        reporter: entry.reporter,
      })).filter((entry: URLhausEntry) => entry.url_status === 'online');
    }

    return SAMPLE_MALWARE_URLS;
  } catch (error) {
    console.error('[URLhaus] Feed fetch error:', error);
    return SAMPLE_MALWARE_URLS;
  }
}

/**
 * Check a URL against URLhaus patterns
 * Used for heuristic detection without full feed
 */
export function checkURLhausUrl(url: string): {
  isMalware: boolean;
  threat?: string;
  confidence: number;
} {
  const normalizedUrl = url.toLowerCase();

  // Common malware distribution patterns
  const malwarePatterns = [
    // Executable downloads
    { pattern: /\.exe(\?|$)/i, threat: 'executable_download' },
    { pattern: /\.scr(\?|$)/i, threat: 'screensaver_executable' },
    { pattern: /\.bat(\?|$)/i, threat: 'batch_script' },
    { pattern: /\.cmd(\?|$)/i, threat: 'command_script' },
    { pattern: /\.ps1(\?|$)/i, threat: 'powershell_script' },
    { pattern: /\.vbs(\?|$)/i, threat: 'vbscript' },
    { pattern: /\.hta(\?|$)/i, threat: 'html_application' },
    { pattern: /\.dll(\?|$)/i, threat: 'dll_download' },

    // Document macros
    { pattern: /\.docm(\?|$)/i, threat: 'macro_enabled_doc' },
    { pattern: /\.xlsm(\?|$)/i, threat: 'macro_enabled_excel' },
    { pattern: /\.pptm(\?|$)/i, threat: 'macro_enabled_ppt' },

    // Common C2 patterns
    { pattern: /\/gate\.php/i, threat: 'c2_gate' },
    { pattern: /\/panel\//i, threat: 'c2_panel' },
    { pattern: /\/loader\//i, threat: 'malware_loader' },
    { pattern: /\/bot\//i, threat: 'botnet' },

    // Suspicious paths
    { pattern: /\/update\.php\?/i, threat: 'suspicious_update' },
    { pattern: /\/check\.php\?/i, threat: 'suspicious_check' },
    { pattern: /\/data\.php\?/i, threat: 'data_exfil' },
  ];

  for (const { pattern, threat } of malwarePatterns) {
    if (pattern.test(normalizedUrl)) {
      return {
        isMalware: true,
        threat,
        confidence: 0.6, // Pattern-based detection is less certain
      };
    }
  }

  // Check for IP-based URLs (common in malware)
  const ipUrlPattern = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  if (ipUrlPattern.test(normalizedUrl)) {
    return {
      isMalware: false, // Not necessarily malware, but suspicious
      threat: 'ip_based_url',
      confidence: 0.4,
    };
  }

  return {
    isMalware: false,
    confidence: 0.5,
  };
}

/**
 * Get threat category description
 */
export function getThreatDescription(threat: string): string {
  const descriptions: Record<string, string> = {
    'malware_download': 'Hosts malware for download',
    'phishing': 'Phishing page',
    'defacement': 'Website defacement',
    'cryptomining': 'Cryptocurrency mining',
    'spam': 'Spam-related activity',
    'executable_download': 'Direct executable download',
    'c2_gate': 'Command & control gate',
    'c2_panel': 'Command & control panel',
    'malware_loader': 'Malware loader/dropper',
    'botnet': 'Botnet infrastructure',
    'data_exfil': 'Data exfiltration endpoint',
  };

  return descriptions[threat] || 'Unknown threat type';
}
