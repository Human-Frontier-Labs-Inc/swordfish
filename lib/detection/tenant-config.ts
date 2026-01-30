/**
 * Tenant Configuration Module - Phase 1: Per-Customer Tuning
 *
 * Allows customization of detection thresholds and settings per tenant/customer.
 * This reduces false positives by allowing industry-specific tuning.
 *
 * Expected Impact: +1 point to detection score (fewer false positives)
 */

export interface TenantConfig {
  tenantId: string;
  name: string;
  industry?: TenantIndustry;
  thresholds: ThresholdConfig;
  allowlists: AllowlistConfig;
  settings: TenantSettings;
  createdAt: Date;
  updatedAt: Date;
}

export type TenantIndustry =
  | 'financial'
  | 'healthcare'
  | 'technology'
  | 'retail'
  | 'manufacturing'
  | 'education'
  | 'government'
  | 'legal'
  | 'media'
  | 'other';

export interface ThresholdConfig {
  // Overall detection threshold (0-100)
  minDetectionScore: number;

  // Per-category thresholds (can override global)
  categories: {
    phishing?: number;
    malware?: number;
    spam?: number;
    bec?: number; // Business Email Compromise
    impersonation?: number;
  };

  // Signal-specific thresholds
  signals: {
    urlRisk?: number;
    attachmentRisk?: number;
    brandImpersonation?: number;
    reputationRisk?: number;
    qrCodeRisk?: number;
  };
}

export interface AllowlistConfig {
  // Domains that should bypass detection
  domains: string[];

  // Specific sender addresses that are always trusted
  senders: string[];

  // IP addresses/ranges that are trusted
  ipRanges: string[];

  // Tracking domains known to be used by this tenant
  trackingDomains: string[];

  // Partner/vendor domains that send legitimate emails
  partnerDomains: string[];
}

export interface TenantSettings {
  // Enable/disable specific detection modules
  enableBrandProtection: boolean;
  enableQRDetection: boolean;
  enableURLClassification: boolean;
  enableAttachmentSandbox: boolean;

  // Action settings
  quarantineThreshold: number; // Score at which to quarantine
  blockThreshold: number; // Score at which to block

  // Notification settings
  notifyOnQuarantine: boolean;
  notifyOnBlock: boolean;

  // Advanced settings
  strictMode: boolean; // More aggressive detection
  learningMode: boolean; // Collect data but don't block
}

/**
 * Default tenant configuration
 */
export const DEFAULT_TENANT_CONFIG: TenantConfig = {
  tenantId: 'default',
  name: 'Default Configuration',
  thresholds: {
    minDetectionScore: 40,
    categories: {
      phishing: 35,
      malware: 30,
      spam: 50,
      bec: 40,
      impersonation: 45,
    },
    signals: {
      urlRisk: 50,
      attachmentRisk: 40,
      brandImpersonation: 45,
      reputationRisk: 55,
      qrCodeRisk: 50,
    },
  },
  allowlists: {
    domains: [],
    senders: [],
    ipRanges: [],
    trackingDomains: [],
    partnerDomains: [],
  },
  settings: {
    enableBrandProtection: true,
    enableQRDetection: true,
    enableURLClassification: true,
    enableAttachmentSandbox: true,
    quarantineThreshold: 50,
    blockThreshold: 70,
    notifyOnQuarantine: true,
    notifyOnBlock: true,
    strictMode: false,
    learningMode: false,
  },
  createdAt: new Date(),
  updatedAt: new Date(),
};

/**
 * Industry-specific preset configurations
 */
export const INDUSTRY_PRESETS: Record<TenantIndustry, Partial<TenantConfig>> = {
  financial: {
    industry: 'financial',
    thresholds: {
      minDetectionScore: 30, // Lower threshold (more sensitive)
      categories: {
        phishing: 25,
        malware: 25,
        spam: 45,
        bec: 30,
        impersonation: 30,
      },
      signals: {
        urlRisk: 40,
        attachmentRisk: 35,
        brandImpersonation: 35,
        reputationRisk: 45,
        qrCodeRisk: 40,
      },
    },
    settings: {
      ...DEFAULT_TENANT_CONFIG.settings,
      strictMode: true,
      quarantineThreshold: 40,
      blockThreshold: 60,
    },
  },

  healthcare: {
    industry: 'healthcare',
    thresholds: {
      minDetectionScore: 35,
      categories: {
        phishing: 30,
        malware: 25, // Very sensitive to malware
        spam: 50,
        bec: 35,
        impersonation: 40,
      },
      signals: {
        urlRisk: 45,
        attachmentRisk: 35, // Sensitive to attachments
        brandImpersonation: 40,
        reputationRisk: 50,
        qrCodeRisk: 45,
      },
    },
    settings: {
      ...DEFAULT_TENANT_CONFIG.settings,
      strictMode: true,
      quarantineThreshold: 45,
      blockThreshold: 65,
    },
  },

  technology: {
    industry: 'technology',
    thresholds: {
      minDetectionScore: 45, // Higher threshold (fewer false positives)
      categories: {
        phishing: 40,
        malware: 35,
        spam: 55,
        bec: 45,
        impersonation: 50,
      },
      signals: {
        urlRisk: 55, // Tech companies get many legitimate links
        attachmentRisk: 45,
        brandImpersonation: 50,
        reputationRisk: 55,
        qrCodeRisk: 55,
      },
    },
    settings: {
      ...DEFAULT_TENANT_CONFIG.settings,
      strictMode: false,
      quarantineThreshold: 55,
      blockThreshold: 75,
    },
  },

  retail: {
    industry: 'retail',
    thresholds: {
      minDetectionScore: 40,
      categories: {
        phishing: 35,
        malware: 30,
        spam: 45, // More tolerant of marketing emails
        bec: 40,
        impersonation: 40,
      },
      signals: {
        urlRisk: 50,
        attachmentRisk: 40,
        brandImpersonation: 40,
        reputationRisk: 50,
        qrCodeRisk: 45, // QR codes common in retail
      },
    },
    settings: {
      ...DEFAULT_TENANT_CONFIG.settings,
      quarantineThreshold: 50,
      blockThreshold: 70,
    },
  },

  manufacturing: {
    industry: 'manufacturing',
    thresholds: {
      minDetectionScore: 38,
      categories: {
        phishing: 35,
        malware: 30,
        spam: 50,
        bec: 35, // Sensitive to BEC (invoice fraud)
        impersonation: 40,
      },
      signals: {
        urlRisk: 50,
        attachmentRisk: 38,
        brandImpersonation: 45,
        reputationRisk: 50,
        qrCodeRisk: 50,
      },
    },
    settings: {
      ...DEFAULT_TENANT_CONFIG.settings,
      quarantineThreshold: 48,
      blockThreshold: 68,
    },
  },

  education: {
    industry: 'education',
    thresholds: {
      minDetectionScore: 45,
      categories: {
        phishing: 40,
        malware: 35,
        spam: 50,
        bec: 45,
        impersonation: 45,
      },
      signals: {
        urlRisk: 55, // Educational links common
        attachmentRisk: 45,
        brandImpersonation: 50,
        reputationRisk: 55,
        qrCodeRisk: 55,
      },
    },
    settings: {
      ...DEFAULT_TENANT_CONFIG.settings,
      strictMode: false,
      quarantineThreshold: 55,
      blockThreshold: 75,
    },
  },

  government: {
    industry: 'government',
    thresholds: {
      minDetectionScore: 30, // Very sensitive
      categories: {
        phishing: 25,
        malware: 20,
        spam: 40,
        bec: 25,
        impersonation: 30,
      },
      signals: {
        urlRisk: 40,
        attachmentRisk: 30,
        brandImpersonation: 35,
        reputationRisk: 40,
        qrCodeRisk: 40,
      },
    },
    settings: {
      ...DEFAULT_TENANT_CONFIG.settings,
      strictMode: true,
      quarantineThreshold: 35,
      blockThreshold: 55,
    },
  },

  legal: {
    industry: 'legal',
    thresholds: {
      minDetectionScore: 35,
      categories: {
        phishing: 30,
        malware: 25,
        spam: 45,
        bec: 30, // Law firms targeted for BEC
        impersonation: 35,
      },
      signals: {
        urlRisk: 45,
        attachmentRisk: 35, // Sensitive to document attachments
        brandImpersonation: 40,
        reputationRisk: 45,
        qrCodeRisk: 50,
      },
    },
    settings: {
      ...DEFAULT_TENANT_CONFIG.settings,
      strictMode: true,
      quarantineThreshold: 45,
      blockThreshold: 65,
    },
  },

  media: {
    industry: 'media',
    thresholds: {
      minDetectionScore: 45,
      categories: {
        phishing: 40,
        malware: 35,
        spam: 50,
        bec: 45,
        impersonation: 45,
      },
      signals: {
        urlRisk: 55,
        attachmentRisk: 45,
        brandImpersonation: 50,
        reputationRisk: 55,
        qrCodeRisk: 55,
      },
    },
    settings: {
      ...DEFAULT_TENANT_CONFIG.settings,
      quarantineThreshold: 55,
      blockThreshold: 75,
    },
  },

  other: {
    industry: 'other',
    thresholds: DEFAULT_TENANT_CONFIG.thresholds,
    settings: DEFAULT_TENANT_CONFIG.settings,
  },
};

/**
 * In-memory tenant configuration store
 * In production, this would be backed by a database
 */
const tenantConfigs = new Map<string, TenantConfig>();

/**
 * Create a new tenant configuration
 */
export function createTenantConfig(
  tenantId: string,
  name: string,
  options: {
    industry?: TenantIndustry;
    customThresholds?: Partial<ThresholdConfig>;
    customAllowlists?: Partial<AllowlistConfig>;
    customSettings?: Partial<TenantSettings>;
  } = {}
): TenantConfig {
  const { industry, customThresholds, customAllowlists, customSettings } = options;

  // Start with default config - deep clone nested objects to avoid shared references
  let config: TenantConfig = {
    ...DEFAULT_TENANT_CONFIG,
    tenantId,
    name,
    // Deep clone thresholds
    thresholds: {
      ...DEFAULT_TENANT_CONFIG.thresholds,
      categories: { ...DEFAULT_TENANT_CONFIG.thresholds.categories },
      signals: { ...DEFAULT_TENANT_CONFIG.thresholds.signals },
    },
    // Deep clone allowlists to avoid mutation of default arrays
    allowlists: {
      domains: [...DEFAULT_TENANT_CONFIG.allowlists.domains],
      senders: [...DEFAULT_TENANT_CONFIG.allowlists.senders],
      ipRanges: [...DEFAULT_TENANT_CONFIG.allowlists.ipRanges],
      trackingDomains: [...DEFAULT_TENANT_CONFIG.allowlists.trackingDomains],
      partnerDomains: [...DEFAULT_TENANT_CONFIG.allowlists.partnerDomains],
    },
    // Deep clone settings
    settings: { ...DEFAULT_TENANT_CONFIG.settings },
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Apply industry preset if specified
  if (industry && INDUSTRY_PRESETS[industry]) {
    const preset = INDUSTRY_PRESETS[industry];
    config = {
      ...config,
      industry,
      thresholds: {
        ...config.thresholds,
        ...preset.thresholds,
        categories: {
          ...config.thresholds.categories,
          ...preset.thresholds?.categories,
        },
        signals: {
          ...config.thresholds.signals,
          ...preset.thresholds?.signals,
        },
      },
      settings: {
        ...config.settings,
        ...preset.settings,
      },
    };
  }

  // Apply custom overrides
  if (customThresholds) {
    config.thresholds = {
      ...config.thresholds,
      ...customThresholds,
      categories: {
        ...config.thresholds.categories,
        ...customThresholds.categories,
      },
      signals: {
        ...config.thresholds.signals,
        ...customThresholds.signals,
      },
    };
  }

  if (customAllowlists) {
    config.allowlists = {
      ...config.allowlists,
      ...customAllowlists,
    };
  }

  if (customSettings) {
    config.settings = {
      ...config.settings,
      ...customSettings,
    };
  }

  // Store the config
  tenantConfigs.set(tenantId, config);

  return config;
}

/**
 * Get tenant configuration by ID
 */
export function getTenantConfig(tenantId: string): TenantConfig {
  return tenantConfigs.get(tenantId) || DEFAULT_TENANT_CONFIG;
}

/**
 * Update tenant configuration
 */
export function updateTenantConfig(
  tenantId: string,
  updates: Partial<Omit<TenantConfig, 'tenantId' | 'createdAt' | 'updatedAt'>>
): TenantConfig | null {
  const existing = tenantConfigs.get(tenantId);
  if (!existing) {
    return null;
  }

  const updated: TenantConfig = {
    ...existing,
    ...updates,
    thresholds: {
      ...existing.thresholds,
      ...updates.thresholds,
      categories: {
        ...existing.thresholds.categories,
        ...updates.thresholds?.categories,
      },
      signals: {
        ...existing.thresholds.signals,
        ...updates.thresholds?.signals,
      },
    },
    allowlists: {
      ...existing.allowlists,
      ...updates.allowlists,
    },
    settings: {
      ...existing.settings,
      ...updates.settings,
    },
    updatedAt: new Date(),
  };

  tenantConfigs.set(tenantId, updated);
  return updated;
}

/**
 * Delete tenant configuration
 */
export function deleteTenantConfig(tenantId: string): boolean {
  return tenantConfigs.delete(tenantId);
}

/**
 * Add domain to tenant allowlist
 */
export function addAllowlistDomain(tenantId: string, domain: string): boolean {
  const config = tenantConfigs.get(tenantId);
  if (!config) return false;

  const domainLower = domain.toLowerCase();
  if (!config.allowlists.domains.includes(domainLower)) {
    config.allowlists.domains.push(domainLower);
    config.updatedAt = new Date();
    return true;
  }
  return false;
}

/**
 * Remove domain from tenant allowlist
 */
export function removeAllowlistDomain(tenantId: string, domain: string): boolean {
  const config = tenantConfigs.get(tenantId);
  if (!config) return false;

  const domainLower = domain.toLowerCase();
  const index = config.allowlists.domains.indexOf(domainLower);
  if (index !== -1) {
    config.allowlists.domains.splice(index, 1);
    config.updatedAt = new Date();
    return true;
  }
  return false;
}

/**
 * Add tracking domain to tenant config
 */
export function addTrackingDomain(tenantId: string, domain: string): boolean {
  const config = tenantConfigs.get(tenantId);
  if (!config) return false;

  const domainLower = domain.toLowerCase();
  if (!config.allowlists.trackingDomains.includes(domainLower)) {
    config.allowlists.trackingDomains.push(domainLower);
    config.updatedAt = new Date();
    return true;
  }
  return false;
}

/**
 * Check if a domain is on the tenant's allowlist
 */
export function isDomainAllowlisted(tenantId: string, domain: string): boolean {
  const config = getTenantConfig(tenantId);
  const domainLower = domain.toLowerCase();

  return (
    config.allowlists.domains.some(d => domainLower === d || domainLower.endsWith(`.${d}`)) ||
    config.allowlists.partnerDomains.some(d => domainLower === d || domainLower.endsWith(`.${d}`))
  );
}

/**
 * Check if a sender is on the tenant's allowlist
 */
export function isSenderAllowlisted(tenantId: string, sender: string): boolean {
  const config = getTenantConfig(tenantId);
  const senderLower = sender.toLowerCase();

  return config.allowlists.senders.includes(senderLower);
}

/**
 * Get the effective threshold for a category
 */
export function getCategoryThreshold(
  tenantId: string,
  category: keyof ThresholdConfig['categories']
): number {
  const config = getTenantConfig(tenantId);
  return config.thresholds.categories[category] ?? config.thresholds.minDetectionScore;
}

/**
 * Get the effective threshold for a signal type
 */
export function getSignalThreshold(
  tenantId: string,
  signal: keyof ThresholdConfig['signals']
): number {
  const config = getTenantConfig(tenantId);
  return config.thresholds.signals[signal] ?? config.thresholds.minDetectionScore;
}

/**
 * Check if a module is enabled for a tenant
 */
export function isModuleEnabled(
  tenantId: string,
  module: keyof Pick<TenantSettings, 'enableBrandProtection' | 'enableQRDetection' | 'enableURLClassification' | 'enableAttachmentSandbox'>
): boolean {
  const config = getTenantConfig(tenantId);
  return config.settings[module];
}

/**
 * Apply tenant-specific scoring adjustments
 */
export function applyTenantScoring(
  tenantId: string,
  baseScore: number,
  category?: keyof ThresholdConfig['categories']
): { adjustedScore: number; action: 'allow' | 'quarantine' | 'block' } {
  const config = getTenantConfig(tenantId);

  // Get the applicable threshold
  const threshold = category
    ? (config.thresholds.categories[category] ?? config.thresholds.minDetectionScore)
    : config.thresholds.minDetectionScore;

  // Adjust score based on strict mode
  let adjustedScore = baseScore;
  if (config.settings.strictMode) {
    adjustedScore = Math.min(100, baseScore * 1.2); // 20% boost in strict mode
  }

  // Determine action
  let action: 'allow' | 'quarantine' | 'block';
  if (adjustedScore >= config.settings.blockThreshold) {
    action = 'block';
  } else if (adjustedScore >= config.settings.quarantineThreshold) {
    action = 'quarantine';
  } else {
    action = 'allow';
  }

  return { adjustedScore, action };
}

/**
 * Get all registered tenant IDs
 */
export function getAllTenantIds(): string[] {
  return Array.from(tenantConfigs.keys());
}

/**
 * Clear all tenant configurations (for testing)
 */
export function clearAllTenantConfigs(): void {
  tenantConfigs.clear();
}
