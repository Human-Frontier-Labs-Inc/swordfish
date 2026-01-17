/**
 * Anomaly Explainer
 * Generates human-readable explanations for detected anomalies
 */

import type { AnomalyResult } from './anomaly-engine';

export interface AnomalyExplanation {
  summary: string;
  details: AnomalyDetail[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  actionRecommendations: string[];
}

export interface AnomalyDetail {
  type: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  evidence?: string;
}

/**
 * Generate human-readable explanation for anomaly detection results
 */
export function generateAnomalyExplanation(result: AnomalyResult): AnomalyExplanation {
  const details: AnomalyDetail[] = [];
  const recommendations: string[] = [];

  // Process volume anomaly
  if (result.volumeAnomaly && result.anomalyTypes.includes('volume')) {
    details.push({
      type: 'volume',
      title: 'Unusual Email Volume',
      description: formatVolumeDescription(result.volumeAnomaly),
      severity: result.volumeAnomaly.severity === 'critical' ? 'critical' :
                result.volumeAnomaly.severity,
      evidence: `${result.volumeAnomaly.actualVolume} emails sent (expected: ~${result.volumeAnomaly.expectedVolume})`,
    });

    recommendations.push(
      'Review recent email activity for this sender',
      'Check if the sender account may be compromised'
    );
  }

  // Process time anomaly
  if (result.timeAnomaly && result.anomalyTypes.includes('time')) {
    details.push({
      type: 'time',
      title: 'Unusual Send Time',
      description: formatTimeDescription(result.timeAnomaly),
      severity: result.timeAnomaly.severity,
      evidence: `Email sent at ${formatHour(result.timeAnomaly.hour)} (probability: ${(result.timeAnomaly.hourProbability * 100).toFixed(1)}%)`,
    });

    recommendations.push(
      'Verify this email was intentionally sent at this time',
      'Check for signs of automated or scheduled sending'
    );
  }

  // Process recipient anomaly
  if (result.recipientAnomaly && result.anomalyTypes.includes('recipient')) {
    details.push({
      type: 'recipient',
      title: 'New or Unknown Recipients',
      description: formatRecipientDescription(result.recipientAnomaly),
      severity: result.recipientAnomaly.severity,
      evidence: result.recipientAnomaly.newDomains?.length
        ? `New domains: ${result.recipientAnomaly.newDomains.join(', ')}`
        : `${result.recipientAnomaly.newRecipientCount} new recipient(s)`,
    });

    recommendations.push(
      'Verify the recipient addresses are legitimate business contacts',
      'Review the sender account for signs of compromise',
      'Check if this is an expected first-time communication'
    );
  }

  // Process content anomaly
  if (result.contentAnomaly && result.anomalyTypes.includes('content')) {
    details.push({
      type: 'content',
      title: 'Unusual Subject Pattern',
      description: formatContentDescription(result.contentAnomaly),
      severity: result.contentAnomaly.severity,
      evidence: formatContentEvidence(result.contentAnomaly),
    });

    recommendations.push(
      'Review the email content for potential phishing or BEC indicators',
      'Verify urgency claims through a separate communication channel'
    );
  }

  // Determine overall risk level
  const riskLevel = determineRiskLevel(result.compositeScore, details);

  // Generate summary
  const summary = generateSummary(result, details);

  // Add general recommendations based on risk level
  if (riskLevel === 'critical' || riskLevel === 'high') {
    recommendations.unshift(
      'Consider quarantining this email for manual review'
    );
  }

  return {
    summary,
    details,
    riskLevel,
    actionRecommendations: [...new Set(recommendations)],
  };
}

function formatVolumeDescription(anomaly: NonNullable<AnomalyResult['volumeAnomaly']>): string {
  const percentIncrease = Math.round(
    ((anomaly.actualVolume - anomaly.expectedVolume) / anomaly.expectedVolume) * 100
  );

  if (anomaly.severity === 'critical') {
    return `Email volume is ${percentIncrease}% above normal baseline, indicating a significant deviation that warrants immediate attention.`;
  } else if (anomaly.severity === 'high') {
    return `Email volume is ${percentIncrease}% above the normal baseline, which is unusual for this sender.`;
  } else {
    return `Email volume is slightly elevated at ${percentIncrease}% above normal.`;
  }
}

function formatTimeDescription(anomaly: NonNullable<AnomalyResult['timeAnomaly']>): string {
  const hourStr = formatHour(anomaly.hour);

  if (anomaly.isWeekend) {
    return `This email was sent on a weekend at ${hourStr}, which is unusual activity for this organization.`;
  }

  if (anomaly.severity === 'high') {
    return `This email was sent at ${hourStr}, an extremely uncommon time for this organization (only ${(anomaly.hourProbability * 100).toFixed(2)}% of emails are sent at this hour).`;
  }

  return `This email was sent at ${hourStr}, which is outside typical business hours for this sender.`;
}

function formatRecipientDescription(anomaly: NonNullable<AnomalyResult['recipientAnomaly']>): string {
  const parts: string[] = [];

  if (anomaly.hasNewRecipient) {
    parts.push(
      `This email is being sent to ${anomaly.newRecipientCount} recipient(s) that have never been contacted before.`
    );
  }

  if (anomaly.hasNewDomain && anomaly.newDomains?.length) {
    parts.push(
      `The email includes recipients from ${anomaly.newDomains.length} previously unknown domain(s): ${anomaly.newDomains.join(', ')}.`
    );
  }

  return parts.join(' ');
}

function formatContentDescription(anomaly: NonNullable<AnomalyResult['contentAnomaly']>): string {
  const issues: string[] = [];

  if (anomaly.urgencyScore >= 0.7) {
    issues.push('high urgency language');
  }

  if (anomaly.allCapsSubject) {
    issues.push('all-capitals formatting');
  }

  if (anomaly.excessivePunctuation) {
    issues.push('excessive punctuation');
  }

  if (issues.length === 0) {
    return 'The email subject contains patterns that deviate from typical communication patterns.';
  }

  return `The email subject contains ${issues.join(', ')}, which is unusual and may indicate a phishing or social engineering attempt.`;
}

function formatContentEvidence(anomaly: NonNullable<AnomalyResult['contentAnomaly']>): string {
  const evidence: string[] = [];

  if (anomaly.urgencyScore > 0) {
    evidence.push(`Urgency score: ${Math.round(anomaly.urgencyScore * 100)}%`);
  }

  if (anomaly.allCapsSubject) {
    evidence.push('Subject is in ALL CAPS');
  }

  if (anomaly.excessivePunctuation) {
    evidence.push('Contains multiple exclamation/question marks');
  }

  return evidence.join('; ') || 'Unusual subject pattern detected';
}

function formatHour(hour: number): string {
  const ampm = hour >= 12 ? 'PM' : 'AM';
  const displayHour = hour % 12 || 12;
  return `${displayHour}:00 ${ampm}`;
}

function determineRiskLevel(
  score: number,
  details: AnomalyDetail[]
): 'low' | 'medium' | 'high' | 'critical' {
  // Check for any critical details
  if (details.some(d => d.severity === 'critical')) {
    return 'critical';
  }

  // Score-based determination
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function generateSummary(result: AnomalyResult, details: AnomalyDetail[]): string {
  if (!result.hasAnomaly || details.length === 0) {
    return 'No significant behavioral anomalies detected.';
  }

  const anomalyNames: Record<string, string> = {
    volume: 'unusual email volume',
    time: 'unusual send time',
    recipient: 'new recipients',
    content: 'suspicious content patterns',
  };

  const detectedAnomalies = result.anomalyTypes
    .map(type => anomalyNames[type] || type)
    .filter(Boolean);

  if (detectedAnomalies.length === 1) {
    return `Behavioral analysis detected ${detectedAnomalies[0]} (Score: ${result.compositeScore}/100).`;
  }

  const lastAnomaly = detectedAnomalies.pop();
  return `Behavioral analysis detected ${detectedAnomalies.join(', ')} and ${lastAnomaly} (Score: ${result.compositeScore}/100).`;
}

/**
 * Format anomaly result for logging/audit purposes
 */
export function formatAnomalyForAudit(result: AnomalyResult): string {
  const lines: string[] = [
    `Anomaly Detection Report`,
    `========================`,
    `Tenant: ${result.tenantId}`,
    `Email ID: ${result.emailId}`,
    `Detected At: ${result.detectedAt.toISOString()}`,
    `Composite Score: ${result.compositeScore}/100`,
    `Has Anomaly: ${result.hasAnomaly}`,
    `Anomaly Types: ${result.anomalyTypes.join(', ') || 'None'}`,
  ];

  if (result.shouldAlert) {
    lines.push(`Alert Status: ALERT TRIGGERED (${result.alertSeverity})`);
  }

  if (result.volumeAnomaly) {
    lines.push(
      ``,
      `Volume Anomaly:`,
      `  - Z-Score: ${result.volumeAnomaly.zScore.toFixed(2)}`,
      `  - Severity: ${result.volumeAnomaly.severity}`,
      `  - Actual: ${result.volumeAnomaly.actualVolume}`,
      `  - Expected: ${result.volumeAnomaly.expectedVolume}`
    );
  }

  if (result.timeAnomaly) {
    lines.push(
      ``,
      `Time Anomaly:`,
      `  - Hour: ${result.timeAnomaly.hour}`,
      `  - Probability: ${(result.timeAnomaly.hourProbability * 100).toFixed(2)}%`,
      `  - Severity: ${result.timeAnomaly.severity}`,
      `  - Is Weekend: ${result.timeAnomaly.isWeekend}`
    );
  }

  if (result.recipientAnomaly) {
    lines.push(
      ``,
      `Recipient Anomaly:`,
      `  - New Recipients: ${result.recipientAnomaly.newRecipientCount}`,
      `  - New Domains: ${result.recipientAnomaly.newDomains?.join(', ') || 'None'}`,
      `  - Severity: ${result.recipientAnomaly.severity}`
    );
  }

  if (result.contentAnomaly) {
    lines.push(
      ``,
      `Content Anomaly:`,
      `  - Urgency Score: ${Math.round(result.contentAnomaly.urgencyScore * 100)}%`,
      `  - All Caps: ${result.contentAnomaly.allCapsSubject}`,
      `  - Excessive Punctuation: ${result.contentAnomaly.excessivePunctuation}`,
      `  - Severity: ${result.contentAnomaly.severity}`
    );
  }

  return lines.join('\n');
}
