/**
 * QR Code Detection Module - Phase 1: Foundation
 *
 * Detects QR codes in email content and analyzes them for threats.
 * "Quishing" (QR phishing) is a growing attack vector where malicious URLs
 * are embedded in QR codes to bypass traditional URL scanning.
 *
 * Phase 1 focuses on:
 * - Detection of QR code images in email attachments
 * - Base64-encoded inline QR image detection
 * - URL extraction from QR codes (when possible)
 *
 * Expected Impact: +2 points to detection score (new attack vector coverage)
 */

export interface QRCodeDetection {
  found: boolean;
  count: number;
  sources: QRCodeSource[];
  extractedUrls: string[];
  riskScore: number; // 0-10
  signals: QRSignal[];
}

export interface QRCodeSource {
  type: 'attachment' | 'inline' | 'html_embedded';
  filename?: string;
  mimeType?: string;
  size?: number;
  contentId?: string;
}

export interface QRSignal {
  type: 'qr_code_present' | 'qr_url_suspicious' | 'qr_url_shortened' | 'qr_multiple' | 'qr_inline_hidden';
  severity: 'info' | 'warning' | 'critical';
  detail: string;
  score: number;
}

/**
 * Common QR code image signatures
 * These are the magic bytes/patterns that identify QR code image formats
 */
const QR_IMAGE_SIGNATURES = {
  // PNG signature
  PNG: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
  // JPEG signature
  JPEG: [0xFF, 0xD8, 0xFF],
  // GIF signature
  GIF87a: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61],
  GIF89a: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61],
  // BMP signature
  BMP: [0x42, 0x4D],
  // WebP signature
  WEBP: [0x52, 0x49, 0x46, 0x46],
};

/**
 * Patterns that suggest QR code content in filenames
 */
const QR_FILENAME_PATTERNS = [
  /qr[-_]?code/i,
  /scan[-_]?me/i,
  /scan[-_]?to[-_]?pay/i,
  /payment[-_]?qr/i,
  /\bqr\b/i,
  /barcode/i,
];

/**
 * Image MIME types that commonly contain QR codes
 */
const QR_CAPABLE_MIME_TYPES = [
  'image/png',
  'image/jpeg',
  'image/jpg',
  'image/gif',
  'image/webp',
  'image/bmp',
  'image/svg+xml',
];

/**
 * Detect potential QR codes in email content
 *
 * @param attachments - Email attachments with metadata
 * @param htmlContent - HTML body of the email
 * @param textContent - Plain text body of the email
 */
export function detectQRCodes(
  attachments: Array<{
    filename: string;
    mimeType: string;
    size: number;
    contentId?: string;
    content?: Buffer | string;
  }>,
  htmlContent?: string,
  textContent?: string
): QRCodeDetection {
  const sources: QRCodeSource[] = [];
  const signals: QRSignal[] = [];
  const extractedUrls: string[] = [];
  let totalScore = 0;

  // 1. Check attachments for potential QR code images
  for (const attachment of attachments) {
    const isQRCandidate = isLikelyQRCode(attachment);
    if (isQRCandidate.likely) {
      sources.push({
        type: 'attachment',
        filename: attachment.filename,
        mimeType: attachment.mimeType,
        size: attachment.size,
        contentId: attachment.contentId,
      });

      // Base signal for QR code detection
      signals.push({
        type: 'qr_code_present',
        severity: 'warning',
        detail: `Potential QR code detected in attachment: ${attachment.filename} (${isQRCandidate.reason})`,
        score: 5,
      });
      totalScore += 5;
    }
  }

  // 2. Check for inline base64-encoded images in HTML
  if (htmlContent) {
    const inlineQRs = detectInlineQRImages(htmlContent);
    for (const inline of inlineQRs) {
      sources.push({
        type: 'inline',
        mimeType: inline.mimeType,
        size: inline.estimatedSize,
      });

      signals.push({
        type: 'qr_inline_hidden',
        severity: 'warning',
        detail: `Inline base64 image detected (${inline.mimeType}, ~${inline.estimatedSize} bytes) - may contain QR code`,
        score: 4,
      });
      totalScore += 4;
    }

    // 3. Check for embedded images that might be QR codes
    const embeddedQRs = detectEmbeddedQRReferences(htmlContent);
    for (const embedded of embeddedQRs) {
      sources.push({
        type: 'html_embedded',
        filename: embedded.src,
      });

      if (embedded.suspicious) {
        signals.push({
          type: 'qr_code_present',
          severity: 'warning',
          detail: `Embedded image with QR-related naming: ${embedded.src}`,
          score: 3,
        });
        totalScore += 3;
      }
    }
  }

  // 4. Multiple QR codes is higher risk (phishing campaigns)
  if (sources.length > 1) {
    signals.push({
      type: 'qr_multiple',
      severity: 'warning',
      detail: `Multiple potential QR codes detected (${sources.length}) - increased phishing risk`,
      score: 3,
    });
    totalScore += 3;
  }

  // Cap score at 10
  const riskScore = Math.min(10, totalScore);

  return {
    found: sources.length > 0,
    count: sources.length,
    sources,
    extractedUrls,
    riskScore,
    signals,
  };
}

/**
 * Check if an attachment is likely a QR code
 */
function isLikelyQRCode(attachment: {
  filename: string;
  mimeType: string;
  size: number;
  content?: Buffer | string;
}): { likely: boolean; reason: string } {
  const { filename, mimeType, size } = attachment;

  // 1. Check MIME type
  if (!QR_CAPABLE_MIME_TYPES.includes(mimeType.toLowerCase())) {
    return { likely: false, reason: 'Not an image type' };
  }

  // 2. Check filename for QR-related patterns
  for (const pattern of QR_FILENAME_PATTERNS) {
    if (pattern.test(filename)) {
      return { likely: true, reason: `Filename matches QR pattern: ${pattern.source}` };
    }
  }

  // 3. Check file size - QR codes are typically small images
  // Most QR code images are between 1KB and 100KB
  if (size > 1000 && size < 100000) {
    // Could be a QR code based on size
    // Additional heuristic: square aspect ratio would be ideal but we can't check without decoding

    // Small images with generic names are suspicious
    const genericNames = /^(image|img|scan|code|pic|photo)\d*\.(png|jpg|jpeg|gif)$/i;
    if (genericNames.test(filename)) {
      return { likely: true, reason: 'Small image with generic filename' };
    }
  }

  // 4. SVG files might contain QR codes
  if (mimeType === 'image/svg+xml') {
    return { likely: true, reason: 'SVG file (commonly used for QR codes)' };
  }

  // 5. Very small PNG/JPEG files are often QR codes
  if (size < 50000 && (mimeType === 'image/png' || mimeType.includes('jpeg'))) {
    // Small image files are potentially QR codes
    // This is a heuristic - actual QR detection requires image processing
    return { likely: true, reason: 'Small image file - potential QR code' };
  }

  return { likely: false, reason: 'Does not match QR code patterns' };
}

/**
 * Detect inline base64-encoded images in HTML
 */
function detectInlineQRImages(html: string): Array<{ mimeType: string; estimatedSize: number }> {
  const results: Array<{ mimeType: string; estimatedSize: number }> = [];

  // Match data URIs in img src, background-image, etc.
  const dataUriPattern = /data:(image\/[^;]+);base64,([A-Za-z0-9+/=]+)/g;

  let match;
  while ((match = dataUriPattern.exec(html)) !== null) {
    const mimeType = match[1];
    const base64Data = match[2];

    // Estimate decoded size (base64 is ~4/3 of original size)
    const estimatedSize = Math.floor(base64Data.length * 0.75);

    // QR codes are typically small
    if (estimatedSize < 100000 && QR_CAPABLE_MIME_TYPES.includes(mimeType)) {
      results.push({ mimeType, estimatedSize });
    }
  }

  return results;
}

/**
 * Detect embedded image references that might be QR codes
 */
function detectEmbeddedQRReferences(html: string): Array<{ src: string; suspicious: boolean }> {
  const results: Array<{ src: string; suspicious: boolean }> = [];

  // Match img tags
  const imgPattern = /<img[^>]+src=["']([^"']+)["'][^>]*>/gi;

  let match;
  while ((match = imgPattern.exec(html)) !== null) {
    const src = match[1];

    // Skip data URIs (handled separately)
    if (src.startsWith('data:')) continue;

    // Check if src suggests QR code
    const suspicious = QR_FILENAME_PATTERNS.some(pattern => pattern.test(src));

    if (suspicious) {
      results.push({ src, suspicious: true });
    }
  }

  return results;
}

/**
 * Analyze extracted URLs from QR codes for threats
 * (Called after actual QR decoding, which requires external library)
 */
export function analyzeQRUrls(urls: string[]): QRSignal[] {
  const signals: QRSignal[] = [];

  for (const url of urls) {
    // Check for URL shorteners (hiding final destination)
    const shortenerPatterns = [
      /bit\.ly/i, /tinyurl\.com/i, /t\.co/i, /goo\.gl/i,
      /ow\.ly/i, /is\.gd/i, /buff\.ly/i, /rebrand\.ly/i,
    ];

    if (shortenerPatterns.some(p => p.test(url))) {
      signals.push({
        type: 'qr_url_shortened',
        severity: 'warning',
        detail: `QR code contains shortened URL: ${url}`,
        score: 4,
      });
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      { pattern: /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, reason: 'IP-based URL' },
      { pattern: /login|verify|confirm|account|secure/i, reason: 'Credential-related keywords' },
      { pattern: /\.ru\/|\.cn\/|\.tk\/|\.ml\//i, reason: 'High-risk TLD' },
    ];

    for (const { pattern, reason } of suspiciousPatterns) {
      if (pattern.test(url)) {
        signals.push({
          type: 'qr_url_suspicious',
          severity: 'critical',
          detail: `QR code URL is suspicious (${reason}): ${url}`,
          score: 7,
        });
      }
    }
  }

  return signals;
}

/**
 * Get a risk assessment summary for QR detection results
 */
export function getQRRiskSummary(detection: QRCodeDetection): string {
  if (!detection.found) {
    return 'No QR codes detected';
  }

  const riskLevel = detection.riskScore >= 7 ? 'HIGH' :
                    detection.riskScore >= 4 ? 'MEDIUM' : 'LOW';

  return `${detection.count} potential QR code(s) detected - Risk: ${riskLevel} (score: ${detection.riskScore}/10)`;
}
