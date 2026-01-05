/**
 * Warning Banner Templates
 * HTML/CSS templates for email warning banners
 */

export type BannerType = 'suspicious' | 'external' | 'phishing' | 'bec' | 'quarantine';

export interface BannerConfig {
  type: BannerType;
  title: string;
  message: string;
  showDetails?: boolean;
  detailsText?: string;
  backgroundColor?: string;
  borderColor?: string;
  iconColor?: string;
}

// Banner color schemes
const BANNER_COLORS: Record<BannerType, { bg: string; border: string; icon: string }> = {
  suspicious: {
    bg: '#FEF3C7',    // Yellow-100
    border: '#F59E0B', // Yellow-500
    icon: '#D97706',   // Yellow-600
  },
  external: {
    bg: '#DBEAFE',    // Blue-100
    border: '#3B82F6', // Blue-500
    icon: '#2563EB',   // Blue-600
  },
  phishing: {
    bg: '#FEE2E2',    // Red-100
    border: '#EF4444', // Red-500
    icon: '#DC2626',   // Red-600
  },
  bec: {
    bg: '#FEE2E2',    // Red-100
    border: '#DC2626', // Red-600
    icon: '#B91C1C',   // Red-700
  },
  quarantine: {
    bg: '#FEF2F2',    // Red-50
    border: '#991B1B', // Red-800
    icon: '#7F1D1D',   // Red-900
  },
};

// Warning icons (SVG)
const WARNING_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>`;

const SHIELD_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>`;

const EXTERNAL_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" x2="21" y1="14" y2="3"/></svg>`;

/**
 * Get default banner configuration for a type
 */
export function getDefaultBannerConfig(type: BannerType): BannerConfig {
  const configs: Record<BannerType, BannerConfig> = {
    suspicious: {
      type: 'suspicious',
      title: 'Caution: Suspicious Email',
      message: 'This email has characteristics commonly found in phishing attempts. Verify the sender before clicking links or providing information.',
      showDetails: true,
    },
    external: {
      type: 'external',
      title: 'External Sender',
      message: 'This email was sent from outside your organization.',
      showDetails: false,
    },
    phishing: {
      type: 'phishing',
      title: 'Warning: Likely Phishing',
      message: 'This email appears to be a phishing attempt. Do not click links, download attachments, or provide any personal information.',
      showDetails: true,
    },
    bec: {
      type: 'bec',
      title: 'Warning: Possible Impersonation',
      message: 'This email may be impersonating someone from your organization. Verify the sender through a separate channel before taking any action.',
      showDetails: true,
    },
    quarantine: {
      type: 'quarantine',
      title: 'Email Released from Quarantine',
      message: 'This email was previously quarantined and has been released by an administrator. Exercise caution.',
      showDetails: false,
    },
  };

  return configs[type];
}

/**
 * Generate HTML banner for email injection
 */
export function generateBannerHTML(config: BannerConfig): string {
  const colors = BANNER_COLORS[config.type];
  const bgColor = config.backgroundColor || colors.bg;
  const borderColor = config.borderColor || colors.border;
  const iconColor = config.iconColor || colors.icon;

  // Choose icon based on type
  let icon = WARNING_ICON;
  if (config.type === 'external') {
    icon = EXTERNAL_ICON;
  } else if (config.type === 'quarantine') {
    icon = SHIELD_ICON;
  }

  return `
<!--[if mso]>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
<tr><td style="padding: 16px;">
<![endif]-->
<div data-swordfish-banner="${config.type}" style="
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background-color: ${bgColor};
  border: 2px solid ${borderColor};
  border-radius: 8px;
  padding: 16px;
  margin: 0 0 16px 0;
  box-sizing: border-box;
">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
    <tr>
      <td width="40" style="vertical-align: top; padding-right: 12px;">
        <div style="color: ${iconColor}; width: 24px; height: 24px;">
          ${icon}
        </div>
      </td>
      <td style="vertical-align: top;">
        <div style="
          font-size: 16px;
          font-weight: 600;
          color: ${iconColor};
          margin: 0 0 4px 0;
        ">${escapeHTML(config.title)}</div>
        <div style="
          font-size: 14px;
          color: #374151;
          line-height: 1.5;
          margin: 0;
        ">${escapeHTML(config.message)}</div>
        ${config.showDetails && config.detailsText ? `
        <div style="
          font-size: 12px;
          color: #6B7280;
          margin-top: 8px;
          padding-top: 8px;
          border-top: 1px solid ${borderColor}40;
        ">${escapeHTML(config.detailsText)}</div>
        ` : ''}
      </td>
    </tr>
  </table>
</div>
<!--[if mso]>
</td></tr></table>
<![endif]-->
`.trim();
}

/**
 * Generate plain text banner for text-only emails
 */
export function generateBannerText(config: BannerConfig): string {
  const separator = '═'.repeat(60);
  const lines = [
    separator,
    `⚠️  ${config.title.toUpperCase()}`,
    '',
    wordWrap(config.message, 58),
  ];

  if (config.showDetails && config.detailsText) {
    lines.push('', wordWrap(config.detailsText, 58));
  }

  lines.push(separator, '');

  return lines.join('\n');
}

/**
 * Escape HTML special characters
 */
function escapeHTML(text: string): string {
  const escapeMap: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, char => escapeMap[char]);
}

/**
 * Word wrap text at specified width
 */
function wordWrap(text: string, width: number): string {
  const words = text.split(' ');
  const lines: string[] = [];
  let currentLine = '';

  for (const word of words) {
    if (currentLine.length + word.length + 1 <= width) {
      currentLine += (currentLine ? ' ' : '') + word;
    } else {
      if (currentLine) lines.push(currentLine);
      currentLine = word;
    }
  }
  if (currentLine) lines.push(currentLine);

  return lines.join('\n');
}
