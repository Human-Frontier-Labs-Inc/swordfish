/**
 * Phase 4b: Enhanced Macro Analysis
 *
 * Advanced VBA/macro detection for Office documents:
 * - Obfuscation technique detection
 * - Auto-execute trigger identification
 * - Suspicious pattern analysis
 *
 * Expected Impact: +1 detection point
 */

import type { Signal } from './types';

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface VBAAnalysisResult {
  isObfuscated: boolean;
  obfuscationTechniques: string[];
  suspiciousPatterns: string[];
  decodedPayloads: string[];
  riskScore: number;
}

export interface MacroInfo {
  name: string;
  code: string;
}

export interface AutoExecTrigger {
  type: string;
  name: string;
  isAutomatic: boolean;
  action?: string;
}

export interface MacroAnalysisResult {
  hasMacros: boolean;
  macroCount?: number;
  hasAutoExec: boolean;
  hasNetworkCalls: boolean;
  hasShellExec: boolean;
  hasFileOperations: boolean;
  isObfuscated: boolean;
  obfuscationTechniques?: string[];
  suspiciousPatterns?: string[];
  autoExecTriggers?: string[];
  suspiciousKeywordCount: number;
  riskScore?: number;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Auto-execute function patterns
 */
const AUTO_EXEC_PATTERNS: Record<string, string> = {
  'Auto_Open': 'document_open',
  'AutoOpen': 'document_open',
  'Document_Open': 'document_open',
  'Workbook_Open': 'workbook_open',
  'Auto_Close': 'document_close',
  'AutoClose': 'document_close',
  'Document_Close': 'document_close',
  'Workbook_Close': 'workbook_close',
  'AutoExec': 'auto_exec',
  'AutoNew': 'auto_new',
};

/**
 * Suspicious VBA patterns with risk weights
 */
const SUSPICIOUS_PATTERNS: Record<string, { pattern: RegExp; name: string; weight: number }> = {
  shell_exec: {
    pattern: /\bShell\b/i,  // Match Shell with or without parentheses
    name: 'shell_execution',
    weight: 30,
  },
  wmi_exec: {
    pattern: /GetObject\s*\(\s*["']winmgmts:/i,
    name: 'wmi_execution',
    weight: 35,
  },
  powershell: {
    pattern: /powershell|pwsh/i,
    name: 'powershell_invocation',
    weight: 30,
  },
  cmd_exec: {
    pattern: /\bcmd\s*(\/c|\/k)/i,
    name: 'cmd_execution',
    weight: 25,
  },
  process_create: {
    pattern: /Win32_Process|\.Create\s*\(/i,
    name: 'process_creation',
    weight: 30,
  },
  download: {
    pattern: /URLDownloadToFile|XMLHTTP|WinHttp|InternetOpen/i,
    name: 'network_call',
    weight: 25,
  },
  file_write: {
    pattern: /FileSystemObject|Open\s+.*For\s+(Output|Append)|SaveToFile/i,
    name: 'file_write',
    weight: 20,
  },
  environ: {
    pattern: /Environ\s*\(/i,
    name: 'environ_abuse',
    weight: 15,
  },
  exfil: {
    pattern: /copy\s+.*\\\*|xcopy|robocopy|exfil/i,  // Match copy patterns including wildcards and exfil keyword
    name: 'data_exfiltration',
    weight: 35,
  },
  registry: {
    pattern: /RegRead|RegWrite|HKEY_|Shell\.RegWrite/i,
    name: 'registry_access',
    weight: 25,
  },
};

/**
 * Obfuscation technique patterns
 */
const OBFUSCATION_PATTERNS: Record<string, { pattern: RegExp; name: string }> = {
  chr_concat: {
    pattern: /Chr\s*\(\s*\d+\s*\)\s*&\s*Chr|Chr\(\d+\)\s*\+\s*Chr/i,
    name: 'chr_concatenation',
  },
  base64: {
    pattern: /[A-Za-z0-9+/=]{20,}|Base64Decode|Base64Encode/i,
    name: 'base64_encoding',
  },
  hex_encoding: {
    pattern: /&H[0-9A-Fa-f]{2}|0x[0-9A-Fa-f]{2,}/g,
    name: 'hex_encoding',
  },
  string_split: {
    pattern: /"[^"]{1,3}"\s*&\s*"[^"]{1,3}"\s*&/i,
    name: 'string_splitting',
  },
  var_obfuscation: {
    pattern: /\b[a-z]{1}[0-9]{1,2}[a-z]{1}\b|\b[A-Z]{10,}\b/g,
    name: 'variable_obfuscation',
  },
  replace_chain: {
    pattern: /Replace\s*\(.*Replace\s*\(/i,
    name: 'replace_chain',
  },
};

// ============================================================================
// Core Analysis Functions
// ============================================================================

/**
 * Analyze VBA code for suspicious patterns and obfuscation
 */
export function analyzeVBAPatterns(vbaCode: string): VBAAnalysisResult {
  const obfuscationTechniques: string[] = [];
  const suspiciousPatterns: string[] = [];
  const decodedPayloads: string[] = [];
  let riskScore = 0;

  // Check for obfuscation techniques
  for (const [key, config] of Object.entries(OBFUSCATION_PATTERNS)) {
    if (config.pattern.test(vbaCode)) {
      obfuscationTechniques.push(config.name);
    }
  }

  // Check for suspicious patterns
  for (const [key, config] of Object.entries(SUSPICIOUS_PATTERNS)) {
    if (config.pattern.test(vbaCode)) {
      suspiciousPatterns.push(config.name);
      riskScore += config.weight;
    }
  }

  // Try to decode base64 payloads
  const base64Matches = vbaCode.match(/["']([A-Za-z0-9+/=]{20,})["']/g);
  if (base64Matches) {
    for (const match of base64Matches) {
      try {
        const encoded = match.replace(/['"]/g, '');
        const decoded = Buffer.from(encoded, 'base64').toString('utf-8');
        // Check if decoded content looks like a command or URL
        if (/^(http|cmd|powershell|wscript)/i.test(decoded)) {
          decodedPayloads.push(decoded);
          suspiciousPatterns.push('base64_payload');
          riskScore += 25;
        }
      } catch {
        // Not valid base64, ignore
      }
    }
  }

  // Boost risk score for obfuscation
  if (obfuscationTechniques.length > 0) {
    riskScore += 20;
    if (obfuscationTechniques.length >= 2) {
      riskScore += 15; // Multiple obfuscation techniques
    }
  }

  // Check for auto-execute patterns (high risk indicator)
  const autoExecPatterns = [
    /Sub\s+Auto_Open/i,
    /Sub\s+AutoOpen/i,
    /Sub\s+Document_Open/i,
    /Sub\s+Workbook_Open/i,
    /Sub\s+AutoExec/i,
  ];

  const hasAutoExec = autoExecPatterns.some(pattern => pattern.test(vbaCode));
  if (hasAutoExec) {
    suspiciousPatterns.push('auto_execute');
    riskScore += 30; // Auto-execute is a major risk indicator
  }

  const isObfuscated = obfuscationTechniques.length > 0;

  return {
    isObfuscated,
    obfuscationTechniques,
    suspiciousPatterns: [...new Set(suspiciousPatterns)],
    decodedPayloads,
    riskScore: Math.min(100, riskScore),
  };
}

/**
 * Identify all auto-execute triggers in macros
 */
export function identifyAutoExecTriggers(macros: MacroInfo[]): AutoExecTrigger[] {
  const triggers: AutoExecTrigger[] = [];

  for (const macro of macros) {
    // Check macro name against auto-exec patterns
    for (const [pattern, type] of Object.entries(AUTO_EXEC_PATTERNS)) {
      if (macro.name.toLowerCase().includes(pattern.toLowerCase()) ||
          macro.code.toLowerCase().includes(`sub ${pattern.toLowerCase()}(`)) {
        // Determine what action the macro performs
        let action: string | undefined;

        if (/\bShell\b/i.test(macro.code)) {
          action = 'shell_execution';
        } else if (/Kill\s+/i.test(macro.code)) {
          action = 'file_deletion';
        } else if (/XMLHTTP|URLDownload/i.test(macro.code)) {
          action = 'network_request';
        } else if (/MsgBox/i.test(macro.code)) {
          action = 'message_display';
        }

        triggers.push({
          type,
          name: macro.name,
          isAutomatic: true,
          action,
        });
      }
    }

    // Also check for event-based triggers in the code itself
    const eventMatches = macro.code.match(/Private\s+Sub\s+(\w+)_(\w+)\s*\(/gi);
    if (eventMatches) {
      for (const match of eventMatches) {
        const parts = match.match(/Private\s+Sub\s+(\w+)_(\w+)/i);
        if (parts) {
          const [, object, event] = parts;
          const type = `${object.toLowerCase()}_${event.toLowerCase()}`;

          if (!triggers.some(t => t.type === type && t.name === macro.name)) {
            // Determine action for event-based triggers too
            let action: string | undefined;
            if (/\bShell\b/i.test(macro.code)) {
              action = 'shell_execution';
            } else if (/Kill\s+/i.test(macro.code)) {
              action = 'file_deletion';
            } else if (/XMLHTTP|URLDownload/i.test(macro.code)) {
              action = 'network_request';
            }

            triggers.push({
              type,
              name: macro.name,
              isAutomatic: event.toLowerCase() === 'open' || event.toLowerCase() === 'close',
              action,
            });
          }
        }
      }
    }
  }

  return triggers;
}

/**
 * Calculate comprehensive macro risk score
 */
export function calculateMacroRiskScore(analysis: MacroAnalysisResult): number {
  let score = 0;

  // Base score for having macros
  if (analysis.hasMacros) {
    score += 5;
  }

  // Auto-execute is high risk
  if (analysis.hasAutoExec) {
    score += 25;
  }

  // Network calls
  if (analysis.hasNetworkCalls) {
    score += 20;
  }

  // Shell execution
  if (analysis.hasShellExec) {
    score += 30;
  }

  // File operations
  if (analysis.hasFileOperations) {
    score += 15;
  }

  // Obfuscation
  if (analysis.isObfuscated) {
    score += 25;
  }

  // Suspicious keyword count
  score += Math.min(20, analysis.suspiciousKeywordCount * 4);

  // Multiple macros
  if (analysis.macroCount && analysis.macroCount > 3) {
    score += 5;
  }

  return Math.min(100, score);
}

/**
 * Convert macro analysis results to detection signals
 */
export function convertMacroAnalysisToSignals(analysis: MacroAnalysisResult): Signal[] {
  const signals: Signal[] = [];

  // Obfuscated macro signal
  if (analysis.isObfuscated) {
    signals.push({
      type: 'macro_obfuscated',
      severity: 'critical',
      score: 35,
      detail: `Obfuscated VBA code detected: ${analysis.obfuscationTechniques?.join(', ') || 'unknown technique'}`,
      metadata: {
        techniques: analysis.obfuscationTechniques,
      },
    });
  }

  // Auto-execute signal
  if (analysis.hasAutoExec || (analysis.autoExecTriggers && analysis.autoExecTriggers.length > 0)) {
    signals.push({
      type: 'macro_auto_exec',
      severity: 'warning',
      score: 25,
      detail: `Auto-execute macro triggers: ${analysis.autoExecTriggers?.join(', ') || 'detected'}`,
      metadata: {
        triggers: analysis.autoExecTriggers,
      },
    });
  }

  // Suspicious patterns signal
  if (analysis.suspiciousPatterns && analysis.suspiciousPatterns.length > 0) {
    const severity = analysis.suspiciousPatterns.some(p =>
      p.includes('shell') || p.includes('wmi') || p.includes('powershell')
    ) ? 'critical' : 'warning';

    signals.push({
      type: 'macro_suspicious_pattern',
      severity,
      score: severity === 'critical' ? 30 : 20,
      detail: `Suspicious macro patterns: ${analysis.suspiciousPatterns.join(', ')}`,
      metadata: {
        patterns: analysis.suspiciousPatterns,
      },
    });
  }

  // Network activity signal
  if (analysis.hasNetworkCalls) {
    signals.push({
      type: 'macro_network_activity',
      severity: 'warning',
      score: 20,
      detail: 'Macro contains network/download capabilities',
    });
  }

  return signals;
}
