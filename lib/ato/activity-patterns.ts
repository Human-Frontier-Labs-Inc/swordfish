/**
 * Activity Patterns Detection
 *
 * Detects anomalous email activity patterns that may indicate
 * account takeover, including sending spikes, unusual recipients,
 * unusual send times, mass forwarding rules, and inbox rule changes.
 */

export interface ActivityEvent {
  type: string;
  timestamp: Date;
  userId: string;
  metadata?: {
    recipients?: string[];
    subject?: string;
    [key: string]: unknown;
  };
}

export interface SendingPattern {
  avgEmailsPerHour: number;
  stdDevEmailsPerHour: number;
  avgEmailsPerDay: number;
  stdDevEmailsPerDay: number;
  peakHours: number[];
}

export interface ActivityBaseline {
  knownRecipients?: string[];
  internalDomains?: string[];
  avgExternalRecipientsPerDay?: number;
  knownExternalDomains?: string[];
  typicalSendHours?: number[];
  typicalTimezone?: string;
  weekendActivity?: boolean;
  sending?: SendingPattern;
  recipients?: {
    knownRecipients: string[];
    internalDomains: string[];
    avgExternalRecipientsPerDay: number;
  };
  timing?: {
    typicalSendHours: number[];
    typicalTimezone: string;
    weekendActivity: boolean;
  };
}

export interface InboxRule {
  id: string;
  name: string;
  createdAt: Date;
  actions: Array<{
    type: string;
    destination?: string;
  }>;
  conditions: Array<{
    field: string;
    operator: string;
    value: string;
  }>;
  enabled: boolean;
}

export interface RuleChange {
  type: 'create' | 'modify' | 'delete';
  ruleId: string;
  ruleName: string;
  changedAt: Date;
  changedBy: string;
  changes?: Record<string, unknown>;
}

export interface AnomalyResult {
  type: string;
  isAnomaly: boolean;
  score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: Record<string, unknown>;
}

export interface CompositeScore {
  overallScore: number;
  isHighRisk: boolean;
  triggeredDetectors: string[];
  patternMatch?: string;
}

export interface ActivityReport {
  userId: string;
  anomalies: AnomalyResult[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  recommendations: string[];
  analyzedAt: Date;
}

// Default baseline for users without history
const DEFAULT_BASELINE: SendingPattern = {
  avgEmailsPerHour: 10,
  stdDevEmailsPerHour: 5,
  avgEmailsPerDay: 50,
  stdDevEmailsPerDay: 20,
  peakHours: [9, 10, 11, 12, 13, 14, 15, 16, 17],
};

/**
 * Detect sending spike compared to baseline
 */
export function detectSendingSpike(
  events: ActivityEvent[],
  baseline: SendingPattern | null
): AnomalyResult {
  const emailEvents = events.filter((e) => e.type === 'email_sent');
  const currentHourCount = emailEvents.length;

  const effectiveBaseline = baseline || DEFAULT_BASELINE;
  const usingDefaultBaseline = baseline === null;

  // Calculate z-score
  const zScore =
    effectiveBaseline.stdDevEmailsPerHour > 0
      ? (currentHourCount - effectiveBaseline.avgEmailsPerHour) / effectiveBaseline.stdDevEmailsPerHour
      : currentHourCount > effectiveBaseline.avgEmailsPerHour * 2
        ? 5
        : 0;

  const isAnomaly = zScore > 2;
  const score = Math.min(100, Math.max(0, zScore * 20));

  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (zScore > 30) severity = 'critical';
  else if (zScore > 4) severity = 'high';
  else if (zScore > 3) severity = 'medium';

  return {
    type: 'sending_spike',
    isAnomaly,
    score,
    severity,
    details: {
      currentCount: currentHourCount,
      expectedCount: effectiveBaseline.avgEmailsPerHour,
      zScore,
      usingDefaultBaseline,
    },
  };
}

/**
 * Detect unusual recipients
 */
export function detectUnusualRecipients(
  events: ActivityEvent[],
  baseline: ActivityBaseline
): AnomalyResult {
  const knownRecipients = new Set(baseline.knownRecipients || []);
  const internalDomains = new Set(baseline.internalDomains || []);
  const knownExternalDomains = new Set(baseline.knownExternalDomains || []);

  const newExternalRecipients: string[] = [];
  const newDomains = new Set<string>();
  const uniqueNewRecipients = new Set<string>();

  for (const event of events) {
    const recipients = event.metadata?.recipients || [];
    for (const recipient of recipients) {
      const domain = recipient.split('@')[1]?.toLowerCase();
      if (!domain) continue;

      const isInternal = internalDomains.has(domain);
      const isKnown = knownRecipients.has(recipient.toLowerCase());
      const isKnownDomain = knownExternalDomains.has(domain);

      if (!isInternal && !isKnown) {
        newExternalRecipients.push(recipient);
        uniqueNewRecipients.add(recipient.toLowerCase());
        if (!isKnownDomain) {
          newDomains.add(domain);
        }
      }
    }
  }

  const avgExternal = baseline.avgExternalRecipientsPerDay || 5;
  const isAnomaly = uniqueNewRecipients.size >= avgExternal * 3 || newDomains.size >= 5;

  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (uniqueNewRecipients.size >= avgExternal * 10) severity = 'high';
  else if (uniqueNewRecipients.size >= avgExternal * 5) severity = 'medium';

  const score = Math.min(100, (uniqueNewRecipients.size / avgExternal) * 20);

  return {
    type: 'unusual_recipients',
    isAnomaly,
    score,
    severity,
    details: {
      newExternalRecipients: newExternalRecipients.length,
      uniqueNewRecipients: uniqueNewRecipients.size,
      newDomains: newDomains.size,
    },
  };
}

/**
 * Get timezone offset in hours (simplified)
 */
function getTimezoneOffset(timezone: string): number {
  const offsets: Record<string, number> = {
    'America/New_York': -5,
    'America/Los_Angeles': -8,
    'America/Chicago': -6,
    'America/Denver': -7,
    'Europe/London': 0,
    'Europe/Paris': 1,
    'Asia/Tokyo': 9,
    'UTC': 0,
  };
  return offsets[timezone] || 0;
}

/**
 * Detect unusual send times
 */
export function detectUnusualSendTime(
  events: ActivityEvent[],
  baseline: ActivityBaseline,
  userTimezone?: string
): AnomalyResult {
  const typicalHours = new Set(baseline.typicalSendHours || [9, 10, 11, 12, 13, 14, 15, 16, 17]);
  const weekendActivity = baseline.weekendActivity ?? true;
  const timezone = userTimezone || baseline.typicalTimezone || 'UTC';
  const tzOffset = getTimezoneOffset(timezone);

  let unusualHour: number | null = null;
  let isWeekend = false;
  let anomalyCount = 0;

  for (const event of events) {
    const date = new Date(event.timestamp);
    // Convert UTC hour to local hour
    let localHour = date.getUTCHours() + tzOffset;
    if (localHour < 0) localHour += 24;
    if (localHour >= 24) localHour -= 24;

    const dayOfWeek = date.getUTCDay();
    const isWeekendDay = dayOfWeek === 0 || dayOfWeek === 6;

    if (!typicalHours.has(localHour)) {
      unusualHour = localHour;
      anomalyCount++;
    }

    if (isWeekendDay && !weekendActivity) {
      isWeekend = true;
      anomalyCount++;
    }
  }

  const isAnomaly = anomalyCount > 0;
  const score = Math.min(100, anomalyCount * 30);

  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (anomalyCount > 5) severity = 'high';
  else if (anomalyCount > 2) severity = 'medium';

  return {
    type: 'unusual_send_time',
    isAnomaly,
    score,
    severity,
    details: {
      unusualHour,
      isWeekend,
      anomalyCount,
    },
  };
}

/**
 * Detect mass forwarding rules
 */
export function detectMassForwardingRules(rules: InboxRule[], internalDomains: string[]): AnomalyResult {
  const internalDomainSet = new Set(internalDomains.map((d) => d.toLowerCase()));

  let forwardingToExternal = false;
  let hidesActivity = false;
  let rapidCreation = false;

  const recentRules = rules.filter((r) => {
    const age = Date.now() - new Date(r.createdAt).getTime();
    return age < 10 * 60 * 1000; // Created in last 10 minutes
  });

  if (recentRules.length >= 3) {
    rapidCreation = true;
  }

  for (const rule of rules) {
    for (const action of rule.actions) {
      if (action.type === 'forward' && action.destination) {
        const domain = action.destination.split('@')[1]?.toLowerCase();
        if (domain && !internalDomainSet.has(domain)) {
          forwardingToExternal = true;
        }
      }

      // Check if rule hides activity (marks as read + deletes/moves)
      const hasMarkAsRead = rule.actions.some((a) => a.type === 'markAsRead');
      const hasDelete = rule.actions.some(
        (a) => a.type === 'moveToFolder' && a.destination?.toLowerCase().includes('deleted')
      );
      if (hasMarkAsRead && hasDelete) {
        hidesActivity = true;
      }
    }

    // Check if rule matches all emails
    const matchesAll = rule.conditions.some(
      (c) => c.field === 'all' || (c.operator === 'matches' && c.value === '*')
    );
    if (matchesAll && forwardingToExternal) {
      hidesActivity = true;
    }
  }

  const isAnomaly = forwardingToExternal || hidesActivity || rapidCreation;

  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (forwardingToExternal && hidesActivity) severity = 'critical';
  else if (forwardingToExternal) severity = 'critical';
  else if (rapidCreation) severity = 'high';

  const score = isAnomaly ? (severity === 'critical' ? 95 : severity === 'high' ? 75 : 50) : 0;

  return {
    type: 'mass_forwarding',
    isAnomaly,
    score,
    severity,
    details: {
      forwardingToExternal,
      hidesActivity,
      rapidCreation,
      ruleCount: rules.length,
    },
  };
}

/**
 * Detect inbox rule changes
 */
export function detectInboxRuleChanges(changes: RuleChange[]): AnomalyResult {
  let deletedSecurityRule = false;
  let bulkModification = false;
  let massDisabled = false;

  // Check for security rule deletion
  for (const change of changes) {
    if (change.type === 'delete') {
      const name = change.ruleName.toLowerCase();
      if (
        name.includes('security') ||
        name.includes('phishing') ||
        name.includes('spam') ||
        name.includes('block')
      ) {
        deletedSecurityRule = true;
      }
    }
  }

  // Check for bulk modifications (many changes in short time)
  const recentChanges = changes.filter((c) => {
    const age = Date.now() - new Date(c.changedAt).getTime();
    return age < 10 * 60 * 1000; // Last 10 minutes
  });

  if (recentChanges.length >= 5) {
    bulkModification = true;
  }

  // Check for mass disable
  const disableChanges = changes.filter(
    (c) => c.type === 'modify' && c.changes && (c.changes as Record<string, unknown>).enabled === false
  );
  if (disableChanges.length >= 3) {
    massDisabled = true;
  }

  const isAnomaly = deletedSecurityRule || bulkModification || massDisabled;

  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (deletedSecurityRule) severity = 'high';
  else if (bulkModification || massDisabled) severity = 'medium';

  const score = isAnomaly ? (severity === 'high' ? 80 : 50) : 0;

  return {
    type: 'inbox_rule_changes',
    isAnomaly,
    score,
    severity,
    details: {
      deletedSecurityRule,
      bulkModification,
      massDisabled,
      changeCount: changes.length,
    },
  };
}

/**
 * Calculate composite anomaly score from multiple results
 */
export function calculateCompositeAnomalyScore(results: AnomalyResult[]): CompositeScore {
  if (results.length === 0) {
    return {
      overallScore: 0,
      isHighRisk: false,
      triggeredDetectors: [],
    };
  }

  const triggeredDetectors = results.filter((r) => r.isAnomaly).map((r) => r.type);

  // Weight by severity
  const severityWeights: Record<string, number> = {
    critical: 2.0,
    high: 1.5,
    medium: 1.0,
    low: 0.5,
  };

  let totalWeightedScore = 0;
  let totalWeight = 0;

  for (const result of results) {
    if (result.isAnomaly) {
      const weight = severityWeights[result.severity] || 1;
      totalWeightedScore += result.score * weight;
      totalWeight += weight;
    }
  }

  const overallScore = totalWeight > 0 ? Math.min(100, totalWeightedScore / totalWeight) : 0;

  // Detect ATO pattern (spike + unusual recipients + unusual time)
  let patternMatch: string | undefined;
  const detectorSet = new Set(triggeredDetectors);
  if (
    detectorSet.has('sending_spike') &&
    detectorSet.has('unusual_recipients') &&
    detectorSet.has('unusual_send_time')
  ) {
    patternMatch = 'likely_ato';
  }

  // Boost score significantly for pattern match (typical ATO signature)
  const finalScore = patternMatch ? Math.min(100, overallScore * 1.35) : overallScore;

  return {
    overallScore: Math.round(finalScore),
    isHighRisk: finalScore >= 50 || triggeredDetectors.some((d) => d === 'mass_forwarding'),
    triggeredDetectors,
    patternMatch,
  };
}

/**
 * Get activity baseline for user
 */
export async function getActivityBaseline(_userId: string): Promise<ActivityBaseline | null> {
  // In real implementation, fetch from database
  return null;
}

/**
 * Update activity baseline for user
 */
export async function updateActivityBaseline(
  _userId: string,
  _events: ActivityEvent[]
): Promise<ActivityBaseline> {
  // In real implementation, calculate and store baseline
  return {
    knownRecipients: [],
    internalDomains: [],
    avgExternalRecipientsPerDay: 5,
    typicalSendHours: [9, 10, 11, 12, 13, 14, 15, 16, 17],
    weekendActivity: false,
  };
}

/**
 * Activity Pattern Detector Class
 */
export class ActivityPatternDetector {
  private baselines: Map<string, ActivityBaseline> = new Map();

  async getBaseline(userId: string): Promise<ActivityBaseline | null> {
    return this.baselines.get(userId) || null;
  }

  async setBaseline(
    userId: string,
    baseline: {
      sending: SendingPattern;
      recipients: {
        knownRecipients: string[];
        internalDomains: string[];
        avgExternalRecipientsPerDay: number;
      };
      timing: {
        typicalSendHours: number[];
        typicalTimezone: string;
        weekendActivity: boolean;
      };
    }
  ): Promise<void> {
    this.baselines.set(userId, {
      sending: baseline.sending,
      knownRecipients: baseline.recipients.knownRecipients,
      internalDomains: baseline.recipients.internalDomains,
      avgExternalRecipientsPerDay: baseline.recipients.avgExternalRecipientsPerDay,
      typicalSendHours: baseline.timing.typicalSendHours,
      typicalTimezone: baseline.timing.typicalTimezone,
      weekendActivity: baseline.timing.weekendActivity,
    });
  }

  async updateBaseline(userId: string, events: ActivityEvent[]): Promise<void> {
    const emailEvents = events.filter((e) => e.type === 'email_sent');

    // Calculate hourly average
    const hourlyGroups = new Map<number, number>();
    for (const event of emailEvents) {
      const hour = new Date(event.timestamp).getUTCHours();
      hourlyGroups.set(hour, (hourlyGroups.get(hour) || 0) + 1);
    }

    const counts = Array.from(hourlyGroups.values());
    const avgEmailsPerHour =
      counts.length > 0 ? counts.reduce((a, b) => a + b, 0) / counts.length : 0;

    // Collect recipients
    const recipients = new Set<string>();
    for (const event of emailEvents) {
      for (const r of event.metadata?.recipients || []) {
        recipients.add(r.toLowerCase());
      }
    }

    const baseline: ActivityBaseline = {
      sending: {
        avgEmailsPerHour,
        stdDevEmailsPerHour: 2,
        avgEmailsPerDay: avgEmailsPerHour * 8,
        stdDevEmailsPerDay: 10,
        peakHours: Array.from(hourlyGroups.keys()),
      },
      knownRecipients: Array.from(recipients),
      internalDomains: [],
      avgExternalRecipientsPerDay: 5,
      typicalSendHours: [9, 10, 11, 12, 13, 14, 15, 16, 17],
      weekendActivity: false,
    };

    this.baselines.set(userId, baseline);
  }

  async analyzeActivity(userId: string, events: ActivityEvent[]): Promise<ActivityReport> {
    const baseline = await this.getBaseline(userId);

    if (!baseline) {
      return {
        userId,
        anomalies: [],
        riskLevel: 'low',
        recommendations: ['Build baseline with more historical data'],
        analyzedAt: new Date(),
      };
    }

    const anomalies: AnomalyResult[] = [];

    // Run all detectors
    const spikeResult = detectSendingSpike(events, baseline.sending || null);
    if (spikeResult.isAnomaly) anomalies.push(spikeResult);

    const recipientResult = detectUnusualRecipients(events, baseline);
    if (recipientResult.isAnomaly) anomalies.push(recipientResult);

    const timeResult = detectUnusualSendTime(events, baseline);
    if (timeResult.isAnomaly) anomalies.push(timeResult);

    // Calculate composite score
    const composite = calculateCompositeAnomalyScore(anomalies);

    let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
    if (composite.overallScore >= 80) riskLevel = 'critical';
    else if (composite.overallScore >= 60) riskLevel = 'high';
    else if (composite.overallScore >= 40) riskLevel = 'medium';

    const recommendations: string[] = [];
    if (anomalies.some((a) => a.type === 'sending_spike')) {
      recommendations.push('Investigate unusual sending volume');
    }
    if (anomalies.some((a) => a.type === 'unusual_recipients')) {
      recommendations.push('Review external recipients for legitimacy');
    }
    if (composite.patternMatch === 'likely_ato') {
      recommendations.push('Immediately verify account ownership');
      recommendations.push('Consider forcing password reset');
    }

    return {
      userId,
      anomalies,
      riskLevel,
      recommendations,
      analyzedAt: new Date(),
    };
  }
}
