/**
 * Banner Injection System
 * Injects warning banners into email HTML/text content
 */

import {
  generateBannerHTML,
  generateBannerText,
  getDefaultBannerConfig,
  type BannerConfig,
  type BannerType,
} from './templates';

export interface InjectionResult {
  success: boolean;
  html?: string;
  text?: string;
  modified: boolean;
  error?: string;
}

/**
 * Inject warning banner into email content
 */
export function injectBanner(
  html: string | undefined,
  text: string | undefined,
  bannerType: BannerType,
  customConfig?: Partial<BannerConfig>
): InjectionResult {
  const config = {
    ...getDefaultBannerConfig(bannerType),
    ...customConfig,
  };

  let modifiedHtml = html;
  let modifiedText = text;
  let modified = false;

  // Inject into HTML if present
  if (html) {
    try {
      modifiedHtml = injectBannerIntoHTML(html, config);
      modified = true;
    } catch (error) {
      return {
        success: false,
        error: `HTML injection failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        modified: false,
      };
    }
  }

  // Inject into plain text if present
  if (text) {
    try {
      modifiedText = injectBannerIntoText(text, config);
      modified = true;
    } catch (error) {
      return {
        success: false,
        error: `Text injection failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        modified: false,
      };
    }
  }

  return {
    success: true,
    html: modifiedHtml,
    text: modifiedText,
    modified,
  };
}

/**
 * Inject banner into HTML email content
 */
function injectBannerIntoHTML(html: string, config: BannerConfig): string {
  const banner = generateBannerHTML(config);

  // Check if banner already exists
  if (html.includes('data-swordfish-banner')) {
    return html; // Don't inject duplicate
  }

  // Strategy 1: Insert after <body> tag
  const bodyMatch = html.match(/<body[^>]*>/i);
  if (bodyMatch) {
    const insertPos = bodyMatch.index! + bodyMatch[0].length;
    return html.slice(0, insertPos) + '\n' + banner + '\n' + html.slice(insertPos);
  }

  // Strategy 2: Insert after opening table in typical email structure
  const tableMatch = html.match(/<table[^>]*>/i);
  if (tableMatch) {
    // Wrap banner in its own row/cell structure
    const wrappedBanner = `
<tr><td style="padding: 0;">
${banner}
</td></tr>`;
    const insertPos = tableMatch.index! + tableMatch[0].length;
    return html.slice(0, insertPos) + wrappedBanner + html.slice(insertPos);
  }

  // Strategy 3: Prepend to content
  return banner + '\n' + html;
}

/**
 * Inject banner into plain text email content
 */
function injectBannerIntoText(text: string, config: BannerConfig): string {
  const banner = generateBannerText(config);

  // Check if banner already exists
  if (text.includes('═'.repeat(10))) {
    return text; // Likely already has a banner
  }

  return banner + text;
}

/**
 * Remove existing Swordfish banners from content
 */
export function removeBanners(html: string | undefined, text: string | undefined): {
  html?: string;
  text?: string;
} {
  let cleanHtml = html;
  let cleanText = text;

  if (html) {
    // Remove HTML banners
    cleanHtml = html.replace(
      /<!--\[if mso\]>[\s\S]*?<!\[endif\]-->\s*<div data-swordfish-banner[^>]*>[\s\S]*?<\/div>\s*<!--\[if mso\]>[\s\S]*?<!\[endif\]-->/gi,
      ''
    );
    // Also try simpler pattern
    cleanHtml = cleanHtml.replace(
      /<div data-swordfish-banner[^>]*>[\s\S]*?<\/div>/gi,
      ''
    );
  }

  if (text) {
    // Remove text banners (between double line separators)
    cleanText = text.replace(/═{20,}\n⚠️[^═]*═{20,}\n+/g, '');
  }

  return { html: cleanHtml, text: cleanText };
}

/**
 * Determine appropriate banner type based on threat signals
 */
export function determineBannerType(
  verdict: string,
  signals: Array<{ type: string; severity: string }>,
  isExternal: boolean = false
): BannerType | null {
  // Check for BEC signals
  const hasBEC = signals.some(s =>
    s.type.startsWith('bec_') ||
    s.type === 'ml_bec_detected' ||
    s.type === 'llm_bec_detected'
  );

  // Check for phishing signals
  const hasPhishing = signals.some(s =>
    s.type === 'ml_phishing_detected' ||
    s.type === 'llm_phishing_detected' ||
    s.type.includes('phishing')
  );

  // Check for critical signals
  const hasCritical = signals.some(s => s.severity === 'critical');

  // Determine banner type
  if (verdict === 'block') {
    return 'quarantine'; // Released from quarantine
  }

  if (hasBEC) {
    return 'bec';
  }

  if (hasPhishing || (verdict === 'quarantine' && hasCritical)) {
    return 'phishing';
  }

  if (verdict === 'suspicious' || signals.length > 0) {
    return 'suspicious';
  }

  if (isExternal) {
    return 'external';
  }

  return null; // No banner needed
}

/**
 * Build details text from signals
 */
export function buildDetailsText(signals: Array<{ type: string; detail: string }>): string {
  if (signals.length === 0) return '';

  const relevantSignals = signals
    .filter(s =>
      s.type !== 'policy' &&
      !s.type.startsWith('ml_') &&
      !s.type.startsWith('llm_')
    )
    .slice(0, 3);

  if (relevantSignals.length === 0) return '';

  return 'Detected: ' + relevantSignals.map(s => s.detail).join('; ');
}
