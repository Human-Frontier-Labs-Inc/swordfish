/**
 * Lookalike Detector
 * Detects domain and email spoofing using Levenshtein distance and homoglyph detection
 */

export interface KnownContact {
  email: string;
  displayName: string;
}

export interface LookalikeMatch {
  email: string;
  displayName: string;
}

export interface LookalikeResult {
  isLookalike: boolean;
  matchedContact?: LookalikeMatch;
  levenshteinDistance?: number;
  domainSimilarity?: number;
  homoglyphDetected: boolean;
  normalizedEmail?: string;
  confidence: number;
}

// Homoglyph mapping - characters that look similar
// Maps FROM lookalike characters TO the standard Latin character they resemble
const HOMOGLYPH_MAP: Record<string, string[]> = {
  // Cyrillic lookalikes
  'a': ['\u0430', '\u00e0', '\u00e1', '\u00e2', '\u00e3', '\u00e4'],  // а, à, á, â, ã, ä
  'c': ['\u0441', '\u00e7'],  // с (Cyrillic), ç
  'd': ['\u0501'],  // ԁ
  'e': ['\u0435', '\u00e8', '\u00e9', '\u00ea', '\u00eb'],  // е, è, é, ê, ë
  'h': ['\u04bb'],  // һ
  'i': ['\u0456', '\u00ec', '\u00ed', '\u00ee', '\u00ef', '\u0131'],  // і, ì, í, î, ï, ı
  'j': ['\u0458'],  // ј
  'k': ['\u043a'],  // к
  'l': ['\u04cf', '\u007c', '1'],  // ӏ, |, 1 (number 1 looks like l)
  'm': ['\u043c'],  // м
  'n': ['\u0578'],  // ո
  'o': ['\u043e', '\u00f2', '\u00f3', '\u00f4', '\u00f5', '\u00f6', '0'],  // о, ò, ó, ô, õ, ö, 0
  'p': ['\u0440'],  // р
  'q': ['\u0566'],  // զ
  's': ['\u0455'],  // ѕ
  'u': ['\u057d', '\u00f9', '\u00fa', '\u00fb', '\u00fc'],  // ս, ù, ú, û, ü
  'v': ['\u0475'],  // ѵ
  'w': ['\u0561'],  // ա
  'x': ['\u0445'],  // х
  'y': ['\u0443', '\u00fd', '\u00ff'],  // у, ý, ÿ
  'z': ['\u0437'],  // з
};

// Number-to-letter substitution map (numbers that look like letters)
const NUMBER_LETTER_MAP: Record<string, string> = {
  '0': 'o',  // 0 looks like o
  '1': 'l',  // 1 looks like l
};

// Reverse mapping for normalization
const REVERSE_HOMOGLYPH_MAP: Map<string, string> = new Map();

// Build reverse mapping
for (const [latin, homoglyphs] of Object.entries(HOMOGLYPH_MAP)) {
  for (const homoglyph of homoglyphs) {
    REVERSE_HOMOGLYPH_MAP.set(homoglyph, latin);
  }
}

export class LookalikeDetector {
  /**
   * Calculate Levenshtein distance between two strings
   */
  levenshteinDistance(str1: string, str2: string): number {
    const m = str1.length;
    const n = str2.length;

    // Handle empty strings
    if (m === 0) return n;
    if (n === 0) return m;

    // Create distance matrix
    const dp: number[][] = Array(m + 1)
      .fill(null)
      .map(() => Array(n + 1).fill(0));

    // Initialize first column
    for (let i = 0; i <= m; i++) {
      dp[i][0] = i;
    }

    // Initialize first row
    for (let j = 0; j <= n; j++) {
      dp[0][j] = j;
    }

    // Fill in the rest of the matrix
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,      // Deletion
          dp[i][j - 1] + 1,      // Insertion
          dp[i - 1][j - 1] + cost // Substitution
        );
      }
    }

    return dp[m][n];
  }

  /**
   * Calculate similarity score between two strings (0-1)
   */
  calculateSimilarity(str1: string, str2: string): number {
    if (str1 === str2) return 1;

    const normalized1 = this.normalizeHomoglyphs(str1.toLowerCase());
    const normalized2 = this.normalizeHomoglyphs(str2.toLowerCase());

    if (normalized1 === normalized2) return 0.99; // Near match with homoglyphs

    const distance = this.levenshteinDistance(normalized1, normalized2);
    const maxLen = Math.max(normalized1.length, normalized2.length);

    if (maxLen === 0) return 1;

    return 1 - distance / maxLen;
  }

  /**
   * Check if a string contains homoglyph characters
   */
  hasHomoglyphs(str: string): boolean {
    if (!str) return false;

    for (const char of str) {
      // Check if it's in the reverse homoglyph map (non-ASCII lookalikes)
      if (REVERSE_HOMOGLYPH_MAP.has(char)) {
        return true;
      }
      // Check for number-letter substitutions (0 for o, 1 for l)
      if (char in NUMBER_LETTER_MAP) {
        return true;
      }
      // Check for Unicode characters outside basic Latin
      const code = char.charCodeAt(0);
      if (code > 127 && /[a-zA-Z0-9]/.test(String.fromCharCode(code)) === false) {
        // Check if it's a letter-like character
        if (/\p{L}/u.test(char)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Normalize homoglyphs to their Latin equivalents
   */
  normalizeHomoglyphs(str: string): string {
    if (!str) return '';

    let result = '';
    for (const char of str) {
      // Check reverse homoglyph map first (non-ASCII lookalikes)
      const replacement = REVERSE_HOMOGLYPH_MAP.get(char);
      if (replacement) {
        result += replacement;
      } else if (char in NUMBER_LETTER_MAP) {
        // Check number-letter substitutions
        result += NUMBER_LETTER_MAP[char];
      } else {
        result += char;
      }
    }

    return result;
  }

  /**
   * Detect mixed script attacks (combining different Unicode scripts)
   */
  detectMixedScript(str: string): boolean {
    let hasLatin = false;
    let hasCyrillic = false;
    let hasGreek = false;

    for (const char of str) {
      const code = char.charCodeAt(0);

      // Basic Latin
      if (code >= 0x0041 && code <= 0x007A) {
        hasLatin = true;
      }
      // Cyrillic
      else if (code >= 0x0400 && code <= 0x04FF) {
        hasCyrillic = true;
      }
      // Greek
      else if (code >= 0x0370 && code <= 0x03FF) {
        hasGreek = true;
      }
    }

    // Mixed script if more than one alphabet detected
    const scriptCount = [hasLatin, hasCyrillic, hasGreek].filter(Boolean).length;
    return scriptCount > 1;
  }

  /**
   * Get known homoglyph substitutions
   */
  getHomoglyphSubstitutions(): Record<string, string[]> {
    // Combine HOMOGLYPH_MAP with number-letter substitutions for completeness
    const result: Record<string, string[]> = { ...HOMOGLYPH_MAP };
    // Add reverse mappings: what numbers look like which letters
    result['0'] = ['O', 'o', '\u043e'];  // 0 looks like O, o, Cyrillic о
    result['1'] = ['l', 'I', '\u04cf', '|'];  // 1 looks like l, I, ӏ, |
    return result;
  }

  /**
   * Detect if an email is a lookalike of known contacts
   */
  async detectLookalike(
    emailAddress: string,
    displayName: string,
    knownContacts: KnownContact[]
  ): Promise<LookalikeResult> {
    const lowerEmail = emailAddress.toLowerCase();
    const normalizedEmail = this.normalizeHomoglyphs(lowerEmail);
    const hasHomoglyphs = this.hasHomoglyphs(lowerEmail);

    // Extract domain
    const [localPart, domain] = lowerEmail.split('@');
    const normalizedDomain = this.normalizeHomoglyphs(domain);

    let bestMatch: LookalikeMatch | undefined;
    let bestDistance = Infinity;
    let bestDomainSimilarity = 0;

    for (const contact of knownContacts) {
      const contactEmail = contact.email.toLowerCase();
      const [contactLocal, contactDomain] = contactEmail.split('@');

      // Check email similarity
      const normalizedContactEmail = this.normalizeHomoglyphs(contactEmail);
      const distance = this.levenshteinDistance(normalizedEmail, normalizedContactEmail);

      // Check domain similarity specifically
      const domainSimilarity = this.calculateSimilarity(normalizedDomain, contactDomain);

      // Consider it a potential lookalike if:
      // 1. Levenshtein distance is small (1-3 characters)
      // 2. Domain is very similar (>80%)
      // 3. Homoglyphs are used and normalized versions match closely
      const isLookalike =
        (distance > 0 && distance <= 3) ||
        (domainSimilarity > 0.85 && domainSimilarity < 1) ||
        (hasHomoglyphs && this.levenshteinDistance(normalizedEmail, normalizedContactEmail) <= 1);

      if (isLookalike && (distance < bestDistance || domainSimilarity > bestDomainSimilarity)) {
        bestMatch = {
          email: contact.email,
          displayName: contact.displayName,
        };
        bestDistance = distance;
        bestDomainSimilarity = Math.max(bestDomainSimilarity, domainSimilarity);
      }
    }

    // Also check display name similarity
    if (!bestMatch && displayName) {
      for (const contact of knownContacts) {
        const nameSimilarity = this.calculateSimilarity(
          displayName.toLowerCase(),
          contact.displayName.toLowerCase()
        );

        if (nameSimilarity > 0.85 && nameSimilarity < 1) {
          bestMatch = {
            email: contact.email,
            displayName: contact.displayName,
          };
          bestDomainSimilarity = nameSimilarity;
          break;
        }
      }
    }

    const isLookalike = bestMatch !== undefined;
    const confidence = isLookalike
      ? Math.max(bestDomainSimilarity, 1 - bestDistance / Math.max(normalizedEmail.length, 1))
      : 0;

    return {
      isLookalike,
      matchedContact: bestMatch,
      levenshteinDistance: bestDistance < Infinity ? bestDistance : undefined,
      domainSimilarity: bestDomainSimilarity > 0 ? bestDomainSimilarity : undefined,
      homoglyphDetected: hasHomoglyphs,
      normalizedEmail,
      confidence,
    };
  }
}
