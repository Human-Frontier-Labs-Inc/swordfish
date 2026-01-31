/**
 * Phase 3: Enhanced Sandbox Layer (+4 points)
 *
 * Integrates AttachmentAnalyzer and SandboxService into the detection pipeline
 * for comprehensive attachment analysis including:
 * - Magic bytes detection (type mismatch)
 * - Macro extraction and analysis
 * - Archive inspection
 * - Double extension detection
 * - RTL override detection
 * - Known malware hash checking
 *
 * Expected Impact: +4 points to detection score
 */

import type { ParsedEmail, Attachment, Signal, LayerResult } from '@/lib/detection/types';
import { analyzeAttachment } from '@/lib/detection/attachment-analyzer';
import { sandboxService } from '@/lib/threat-intel/sandbox';

/**
 * Options for attachment analysis
 */
export interface AnalysisOptions {
  checkSandbox?: boolean;
  skipDynamicAnalysis?: boolean;
  timeoutMs?: number;
}

/**
 * Result from deep attachment analysis
 */
export interface DeepAttachmentResult {
  filename: string;
  riskScore: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  typeMismatch: boolean;
  hasDoubleExtension: boolean;
  hasRtlOverride: boolean;
  hasMacros: boolean;
  isEncrypted: boolean;
  isExecutable: boolean;
  signals: Signal[];
  archiveContents?: {
    entries: Array<{ filename: string; size: number; isDirectory: boolean }>;
    totalFiles: number;
    totalDirectories: number;
    containsExecutable: boolean;
    containsMacroDocument: boolean;
    isPasswordProtected: boolean;
    nestingLevel: number;
  };
  sandboxResult?: {
    verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
    malwareFamily?: string;
    sources?: string[];
  };
}

/**
 * Extended layer result for sandbox analysis
 */
export interface EnhancedSandboxResult extends LayerResult {
  attachmentsAnalyzed: number;
  attachmentResults?: DeepAttachmentResult[];
}

/**
 * Analyze a single attachment deeply
 */
export async function analyzeAttachmentDeep(
  attachment: Attachment,
  options: AnalysisOptions = {}
): Promise<DeepAttachmentResult> {
  const signals: Signal[] = [];

  // Get content buffer
  const buffer = attachment.content || Buffer.alloc(0);

  // Run attachment analyzer
  const analysis = await analyzeAttachment(buffer, attachment.filename);

  // Generate signals from risk factors
  if (analysis.riskFactors && analysis.riskFactors.length > 0) {
    for (const factor of analysis.riskFactors) {
      const signalType = mapRiskFactorToSignalType(factor);
      const severity = analysis.riskLevel === 'critical' || analysis.riskLevel === 'high'
        ? 'critical'
        : analysis.riskLevel === 'medium' ? 'warning' : 'info';
      signals.push({
        type: signalType,
        severity,
        score: getSignalScore(signalType, severity),
        detail: factor,
      });
    }
  }

  // Check sandbox if requested and hash available
  let sandboxResult: DeepAttachmentResult['sandboxResult'];
  if (options.checkSandbox && attachment.hash) {
    try {
      const hashResult = await sandboxService.checkHash(attachment.hash);

      if (hashResult.found && hashResult.verdict === 'malicious') {
        sandboxResult = {
          verdict: 'malicious',
          malwareFamily: hashResult.malwareFamily,
          sources: ['VirusTotal'], // Default source since HashCheckResult doesn't track sources
        };

        signals.push({
          type: 'attachment_malware',
          severity: 'critical',
          score: 50,
          detail: `Known malware detected: ${hashResult.malwareFamily || 'Unknown family'}`,
          metadata: { malwareFamily: hashResult.malwareFamily },
        });
      } else {
        sandboxResult = {
          verdict: hashResult.verdict || 'unknown',
        };
      }
    } catch {
      // Sandbox check failed, continue with static analysis only
      sandboxResult = { verdict: 'unknown' };
    }
  }

  // Build archive contents if available
  let archiveContents: DeepAttachmentResult['archiveContents'];
  if (analysis.archiveContents) {
    // Map ArchiveEntry[] to simpler format and calculate derived values
    const entries = analysis.archiveContents.entries.map(e => ({
      filename: e.filename,
      size: e.size,
      isDirectory: e.isDirectory,
    }));
    const totalFiles = entries.filter(e => !e.isDirectory).length;
    const totalDirectories = entries.filter(e => e.isDirectory).length;
    const containsExecutable = analysis.archiveContents.entries.some(e => e.isDangerous);
    const containsMacroDocument = analysis.archiveContents.entries.some(e =>
      e.extension === '.docm' || e.extension === '.xlsm' || e.extension === '.pptm'
    );

    archiveContents = {
      entries,
      totalFiles,
      totalDirectories,
      containsExecutable,
      containsMacroDocument,
      isPasswordProtected: analysis.archiveContents.isPasswordProtected || false,
      nestingLevel: analysis.archiveContents.maxDepth || 0,
    };
  }

  return {
    filename: attachment.filename,
    riskScore: analysis.riskScore || 0,
    riskLevel: analysis.riskLevel || 'safe',
    typeMismatch: analysis.extensionMismatch || false,
    hasDoubleExtension: analysis.hasDoubleExtension || false,
    hasRtlOverride: analysis.hasRtlOverride || false,
    hasMacros: analysis.hasMacros || false,
    isEncrypted: analysis.isPasswordProtected || false,
    isExecutable: analysis.isExecutable || false,
    signals,
    archiveContents,
    sandboxResult,
  };
}

/**
 * Map risk factor string to signal type
 */
function mapRiskFactorToSignalType(factor: string): Signal['type'] {
  const lowerFactor = factor.toLowerCase();

  if (lowerFactor.includes('macro')) return 'macro_enabled';
  if (lowerFactor.includes('executable')) return 'executable';
  if (lowerFactor.includes('password') || lowerFactor.includes('encrypted')) return 'password_protected_archive';
  if (lowerFactor.includes('malware')) return 'attachment_malware';
  if (lowerFactor.includes('double extension')) return 'dangerous_attachment';
  if (lowerFactor.includes('rtl') || lowerFactor.includes('override')) return 'dangerous_attachment';
  if (lowerFactor.includes('mismatch')) return 'dangerous_attachment';
  if (lowerFactor.includes('script')) return 'dangerous_attachment';
  if (lowerFactor.includes('archive')) return 'dangerous_attachment';

  return 'dangerous_attachment';
}

/**
 * Get score for a signal type
 */
function getSignalScore(type: string, severity: string): number {
  const severityScores: Record<string, number> = {
    critical: 40,
    warning: 20,
    info: 5,
  };

  const typeBonus: Record<string, number> = {
    attachment_malware: 50,
    dangerous_attachment: 40,
    executable: 35,
    macro_enabled: 25,
    password_protected_archive: 15,
  };

  return typeBonus[type] || severityScores[severity] || 10;
}

/**
 * Run enhanced sandbox analysis on email attachments
 */
export async function runEnhancedSandboxAnalysis(
  email: ParsedEmail,
  tenantId: string,
  options: AnalysisOptions = {}
): Promise<EnhancedSandboxResult> {
  const startTime = Date.now();

  // Skip if no attachments
  if (!email.attachments || email.attachments.length === 0) {
    return {
      layer: 'sandbox',
      score: 0,
      confidence: 1,
      signals: [],
      processingTimeMs: Date.now() - startTime,
      skipped: true,
      skipReason: 'No attachments to analyze',
      attachmentsAnalyzed: 0,
    };
  }

  try {
    const attachmentResults: DeepAttachmentResult[] = [];
    const allSignals: Signal[] = [];
    let maxRiskScore = 0;
    let hasContent = false;

    // Analyze each attachment
    for (const attachment of email.attachments) {
      try {
        const result = await analyzeAttachmentDeep(attachment, options);
        attachmentResults.push(result);

        // Track if we have actual content to analyze
        if (attachment.content && attachment.content.length > 0) {
          hasContent = true;
        }

        // Collect signals
        for (const signal of result.signals) {
          allSignals.push(signal);
        }

        // Track max risk
        maxRiskScore = Math.max(maxRiskScore, result.riskScore);
      } catch (error) {
        // Individual attachment analysis failed, continue with others
        console.error(`Error analyzing attachment ${attachment.filename}:`, error);
      }
    }

    // If all attachment analyses failed
    if (attachmentResults.length === 0 && email.attachments.length > 0) {
      return {
        layer: 'sandbox',
        score: 0,
        confidence: 0.3,
        signals: [],
        processingTimeMs: Date.now() - startTime,
        skipped: true,
        skipReason: 'All attachment analyses failed due to error',
        attachmentsAnalyzed: 0,
      };
    }

    // Calculate aggregate score (use max score approach for attachments)
    const aggregateScore = calculateAggregateScore(attachmentResults);

    // Calculate confidence based on analysis depth
    const confidence = calculateConfidence(attachmentResults, hasContent, options);

    return {
      layer: 'sandbox',
      score: aggregateScore,
      confidence,
      signals: allSignals,
      processingTimeMs: Date.now() - startTime,
      attachmentsAnalyzed: attachmentResults.length,
      attachmentResults,
      metadata: {
        tenantId,
        attachmentCount: email.attachments.length,
        maxRiskScore,
      },
    };
  } catch (error) {
    // Complete failure
    return {
      layer: 'sandbox',
      score: 0,
      confidence: 0.2,
      signals: [],
      processingTimeMs: Date.now() - startTime,
      skipped: true,
      skipReason: `Analysis error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      attachmentsAnalyzed: 0,
    };
  }
}

/**
 * Calculate aggregate score from multiple attachment results
 */
function calculateAggregateScore(results: DeepAttachmentResult[]): number {
  if (results.length === 0) return 0;

  // Use max score for critical findings
  const maxScore = Math.max(...results.map(r => r.riskScore));

  // Add small contribution from additional risky attachments
  const otherScores = results
    .map(r => r.riskScore)
    .filter(s => s > 20)
    .sort((a, b) => b - a)
    .slice(1); // Skip the max

  const additionalRisk = otherScores.reduce((sum, score) => sum + score * 0.1, 0);

  return Math.min(100, maxScore + additionalRisk);
}

/**
 * Calculate confidence based on analysis depth
 */
function calculateConfidence(
  results: DeepAttachmentResult[],
  hasContent: boolean,
  options: AnalysisOptions
): number {
  let confidence = 0.5; // Base confidence

  // Higher confidence if we have actual content to analyze
  if (hasContent) {
    confidence += 0.3;
  }

  // Higher confidence if sandbox was checked
  if (options.checkSandbox && results.some(r => r.sandboxResult)) {
    confidence += 0.1;
  }

  // Lower confidence if analysis was limited
  if (options.skipDynamicAnalysis) {
    confidence -= 0.1;
  }

  // Higher confidence with more detailed results
  if (results.some(r => r.archiveContents)) {
    confidence += 0.05;
  }
  if (results.some(r => r.hasMacros)) {
    confidence += 0.05;
  }

  return Math.min(1, Math.max(0.2, confidence));
}
