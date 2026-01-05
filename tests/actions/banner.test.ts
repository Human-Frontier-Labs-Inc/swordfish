/**
 * Tests for Banner Injection System
 */

import { describe, it, expect } from 'vitest';
import {
  generateBannerHTML,
  generateBannerText,
  getDefaultBannerConfig,
  type BannerType,
} from '@/lib/actions/banner/templates';
import {
  injectBanner,
  removeBanners,
  determineBannerType,
  buildDetailsText,
} from '@/lib/actions/banner/inject';

describe('Banner Templates', () => {
  describe('getDefaultBannerConfig', () => {
    const bannerTypes: BannerType[] = ['suspicious', 'external', 'phishing', 'bec', 'quarantine'];

    it.each(bannerTypes)('should return config for %s banner', (type) => {
      const config = getDefaultBannerConfig(type);
      expect(config.type).toBe(type);
      expect(config.title).toBeDefined();
      expect(config.message).toBeDefined();
    });

    it('should have different titles for each type', () => {
      const titles = bannerTypes.map(t => getDefaultBannerConfig(t).title);
      const uniqueTitles = new Set(titles);
      expect(uniqueTitles.size).toBe(bannerTypes.length);
    });
  });

  describe('generateBannerHTML', () => {
    it('should generate valid HTML banner', () => {
      const config = getDefaultBannerConfig('suspicious');
      const html = generateBannerHTML(config);

      expect(html).toContain('data-swordfish-banner="suspicious"');
      expect(html).toContain(config.title);
      expect(html).toContain(config.message);
    });

    it('should include MSO conditional comments', () => {
      const config = getDefaultBannerConfig('phishing');
      const html = generateBannerHTML(config);

      expect(html).toContain('<!--[if mso]>');
      expect(html).toContain('<![endif]-->');
    });

    it('should include details when showDetails is true', () => {
      const config = getDefaultBannerConfig('suspicious');
      config.detailsText = 'Test details here';
      const html = generateBannerHTML(config);

      expect(html).toContain('Test details here');
    });

    it('should use custom colors when provided', () => {
      const config = getDefaultBannerConfig('external');
      config.backgroundColor = '#FF0000';
      config.borderColor = '#00FF00';
      const html = generateBannerHTML(config);

      expect(html).toContain('#FF0000');
      expect(html).toContain('#00FF00');
    });
  });

  describe('generateBannerText', () => {
    it('should generate plain text banner', () => {
      const config = getDefaultBannerConfig('phishing');
      const text = generateBannerText(config);

      expect(text).toContain('═');
      expect(text).toContain('⚠️');
      expect(text).toContain(config.title.toUpperCase());
    });

    it('should include details when provided', () => {
      const config = getDefaultBannerConfig('bec');
      config.detailsText = 'Additional security details';
      const text = generateBannerText(config);

      expect(text).toContain('Additional security details');
    });

    it('should word wrap long messages', () => {
      const config = getDefaultBannerConfig('quarantine');
      const text = generateBannerText(config);

      // Each line should be <= 58 chars (excluding separator lines)
      const lines = text.split('\n').filter(l => !l.includes('═'));
      lines.forEach(line => {
        if (line.trim() && !line.includes('⚠️')) {
          expect(line.length).toBeLessThanOrEqual(60);
        }
      });
    });
  });
});

describe('Banner Injection', () => {
  describe('injectBanner', () => {
    it('should inject banner into HTML with body tag', () => {
      const html = '<html><body><p>Hello</p></body></html>';
      const result = injectBanner(html, undefined, 'suspicious');

      expect(result.success).toBe(true);
      expect(result.modified).toBe(true);
      expect(result.html).toContain('data-swordfish-banner');
    });

    it('should inject banner into HTML with table structure', () => {
      const html = '<table><tr><td>Content</td></tr></table>';
      const result = injectBanner(html, undefined, 'external');

      expect(result.success).toBe(true);
      expect(result.html).toContain('data-swordfish-banner');
    });

    it('should prepend banner when no recognizable structure', () => {
      const html = '<div>Simple content</div>';
      const result = injectBanner(html, undefined, 'phishing');

      expect(result.success).toBe(true);
      expect(result.html).toContain('data-swordfish-banner');
      expect(result.html?.startsWith('<!--[if mso]>')).toBe(true);
    });

    it('should inject banner into plain text', () => {
      const text = 'Hello, this is an email.';
      const result = injectBanner(undefined, text, 'bec');

      expect(result.success).toBe(true);
      expect(result.modified).toBe(true);
      expect(result.text).toContain('═');
      expect(result.text).toContain('⚠️');
    });

    it('should inject banner into both HTML and text', () => {
      const html = '<body><p>Content</p></body>';
      const text = 'Content';
      const result = injectBanner(html, text, 'quarantine');

      expect(result.success).toBe(true);
      expect(result.html).toContain('data-swordfish-banner');
      expect(result.text).toContain('═');
    });

    it('should not inject duplicate banners', () => {
      const html = '<body><div data-swordfish-banner="suspicious">Existing</div></body>';
      const result = injectBanner(html, undefined, 'phishing');

      expect(result.success).toBe(true);
      expect(result.html).toBe(html); // Unchanged
    });

    it('should apply custom config', () => {
      const html = '<body></body>';
      const result = injectBanner(html, undefined, 'suspicious', {
        title: 'Custom Title',
        message: 'Custom Message',
      });

      expect(result.success).toBe(true);
      expect(result.html).toContain('Custom Title');
      expect(result.html).toContain('Custom Message');
    });
  });

  describe('removeBanners', () => {
    it('should remove HTML banner', () => {
      const html = '<div data-swordfish-banner="test">Banner</div><p>Content</p>';
      const { html: cleaned } = removeBanners(html, undefined);

      expect(cleaned).not.toContain('data-swordfish-banner');
      expect(cleaned).toContain('Content');
    });

    it('should remove text banner', () => {
      const text = '════════════════════════════════\n⚠️  WARNING\nMessage\n════════════════════════════════\n\nActual content';
      const { text: cleaned } = removeBanners(undefined, text);

      expect(cleaned).not.toContain('═');
      expect(cleaned).toContain('Actual content');
    });

    it('should handle content without banners', () => {
      const html = '<p>No banner here</p>';
      const text = 'Plain text without banner';
      const { html: cleanedHtml, text: cleanedText } = removeBanners(html, text);

      expect(cleanedHtml).toBe(html);
      expect(cleanedText).toBe(text);
    });
  });

  describe('determineBannerType', () => {
    it('should return bec for BEC signals', () => {
      const signals = [{ type: 'bec_wire_transfer', severity: 'critical' }];
      expect(determineBannerType('suspicious', signals)).toBe('bec');
    });

    it('should return phishing for phishing signals', () => {
      const signals = [{ type: 'ml_phishing_detected', severity: 'critical' }];
      expect(determineBannerType('suspicious', signals)).toBe('phishing');
    });

    it('should return quarantine for block verdict', () => {
      expect(determineBannerType('block', [])).toBe('quarantine');
    });

    it('should return suspicious for suspicious signals', () => {
      const signals = [{ type: 'suspicious_sender', severity: 'warning' }];
      expect(determineBannerType('suspicious', signals)).toBe('suspicious');
    });

    it('should return external for external sender', () => {
      expect(determineBannerType('pass', [], true)).toBe('external');
    });

    it('should return null when no banner needed', () => {
      expect(determineBannerType('pass', [])).toBeNull();
    });
  });

  describe('buildDetailsText', () => {
    it('should build details from signals', () => {
      const signals = [
        { type: 'suspicious_domain', detail: 'Domain is suspicious' },
        { type: 'failed_spf', detail: 'SPF check failed' },
      ];
      const details = buildDetailsText(signals);

      expect(details).toContain('Detected:');
      expect(details).toContain('Domain is suspicious');
      expect(details).toContain('SPF check failed');
    });

    it('should filter out policy and ML signals', () => {
      const signals = [
        { type: 'policy', detail: 'Policy match' },
        { type: 'ml_confidence', detail: 'ML score' },
        { type: 'suspicious_link', detail: 'Link issue' },
      ];
      const details = buildDetailsText(signals);

      expect(details).not.toContain('Policy match');
      expect(details).not.toContain('ML score');
      expect(details).toContain('Link issue');
    });

    it('should limit to 3 signals', () => {
      const signals = [
        { type: 'sig1', detail: 'Detail 1' },
        { type: 'sig2', detail: 'Detail 2' },
        { type: 'sig3', detail: 'Detail 3' },
        { type: 'sig4', detail: 'Detail 4' },
      ];
      const details = buildDetailsText(signals);

      expect(details).toContain('Detail 1');
      expect(details).toContain('Detail 2');
      expect(details).toContain('Detail 3');
      expect(details).not.toContain('Detail 4');
    });

    it('should return empty string for no signals', () => {
      expect(buildDetailsText([])).toBe('');
    });
  });
});
