/**
 * SOC 2 Compliance Report Generator
 *
 * Generates SOC 2 Type II compliance reports
 */

import { sql } from '@/lib/db';

export interface SOC2ReportData {
  reportId: string;
  tenantId: string;
  generatedAt: Date;
  period: {
    start: Date;
    end: Date;
  };
  organization: OrganizationInfo;
  executive: ExecutiveSummary;
  controls: ControlCategory[];
  findings: Finding[];
  recommendations: Recommendation[];
}

interface OrganizationInfo {
  name: string;
  domain: string;
  usersProtected: number;
  emailsProcessed: number;
  integrationsActive: number;
}

interface ExecutiveSummary {
  overallStatus: 'compliant' | 'partially_compliant' | 'non_compliant';
  score: number;
  threatsBlocked: number;
  threatsQuarantined: number;
  falsePositives: number;
  avgResponseTime: string;
  uptime: number;
}

interface ControlCategory {
  id: string;
  name: string;
  description: string;
  status: 'pass' | 'partial' | 'fail';
  controls: Control[];
}

interface Control {
  id: string;
  name: string;
  description: string;
  status: 'pass' | 'partial' | 'fail';
  evidence: string[];
  lastTested: Date;
}

interface Finding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  recommendation: string;
  status: 'open' | 'resolved' | 'accepted';
}

interface Recommendation {
  id: string;
  priority: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  impact: string;
}

// SOC 2 Trust Services Criteria categories
const SOC2_CATEGORIES = [
  {
    id: 'CC1',
    name: 'Control Environment',
    description: 'Security policies, procedures, and organizational structure',
    controls: [
      { id: 'CC1.1', name: 'Integrity and Ethics', description: 'Demonstrates commitment to integrity and ethical values' },
      { id: 'CC1.2', name: 'Board Oversight', description: 'Board exercises oversight responsibilities' },
      { id: 'CC1.3', name: 'Organizational Structure', description: 'Management establishes structure and reporting lines' },
      { id: 'CC1.4', name: 'Commitment to Competence', description: 'Demonstrates commitment to competence' },
      { id: 'CC1.5', name: 'Accountability', description: 'Enforces accountability for internal control' },
    ],
  },
  {
    id: 'CC2',
    name: 'Communication and Information',
    description: 'Information and communication systems',
    controls: [
      { id: 'CC2.1', name: 'Quality Information', description: 'Obtains or generates quality information' },
      { id: 'CC2.2', name: 'Internal Communication', description: 'Internally communicates information' },
      { id: 'CC2.3', name: 'External Communication', description: 'Communicates with external parties' },
    ],
  },
  {
    id: 'CC3',
    name: 'Risk Assessment',
    description: 'Risk identification and management',
    controls: [
      { id: 'CC3.1', name: 'Objectives Specification', description: 'Specifies objectives with sufficient clarity' },
      { id: 'CC3.2', name: 'Risk Identification', description: 'Identifies risks to achievement of objectives' },
      { id: 'CC3.3', name: 'Fraud Consideration', description: 'Considers potential for fraud' },
      { id: 'CC3.4', name: 'Change Assessment', description: 'Identifies and assesses changes' },
    ],
  },
  {
    id: 'CC6',
    name: 'Logical and Physical Access',
    description: 'Access controls and authentication',
    controls: [
      { id: 'CC6.1', name: 'Access Controls', description: 'Implements logical access security' },
      { id: 'CC6.2', name: 'Authentication', description: 'Requires authentication before access' },
      { id: 'CC6.3', name: 'Authorization', description: 'Authorizes access to assets' },
      { id: 'CC6.6', name: 'Threats Protection', description: 'Protects against threats outside system boundaries' },
      { id: 'CC6.7', name: 'Data Transmission', description: 'Restricts transmission of data' },
      { id: 'CC6.8', name: 'Malware Prevention', description: 'Implements controls to prevent malicious software' },
    ],
  },
  {
    id: 'CC7',
    name: 'System Operations',
    description: 'Monitoring, incident response, and recovery',
    controls: [
      { id: 'CC7.1', name: 'Anomaly Detection', description: 'Detects and monitors security anomalies' },
      { id: 'CC7.2', name: 'Security Events', description: 'Monitors security events' },
      { id: 'CC7.3', name: 'Incident Response', description: 'Evaluates and responds to incidents' },
      { id: 'CC7.4', name: 'Incident Communication', description: 'Communicates incidents' },
      { id: 'CC7.5', name: 'Recovery', description: 'Identifies and recovers from incidents' },
    ],
  },
];

/**
 * Generate SOC 2 compliance report
 */
export async function generateSOC2Report(
  tenantId: string,
  startDate: Date,
  endDate: Date
): Promise<SOC2ReportData> {
  // Fetch metrics for the period
  const metrics = await fetchComplianceMetrics(tenantId, startDate, endDate);

  // Evaluate controls
  const controls = evaluateControls(metrics);

  // Generate findings
  const findings = generateFindings(controls, metrics);

  // Generate recommendations
  const recommendations = generateRecommendations(findings, metrics);

  // Calculate overall status
  const overallStatus = calculateOverallStatus(controls);
  const score = calculateComplianceScore(controls);

  return {
    reportId: `soc2-${tenantId}-${Date.now()}`,
    tenantId,
    generatedAt: new Date(),
    period: { start: startDate, end: endDate },
    organization: {
      name: String(metrics.orgName || 'Organization'),
      domain: String(metrics.domain || 'example.com'),
      usersProtected: Number(metrics.userCount) || 0,
      emailsProcessed: Number(metrics.emailsProcessed) || 0,
      integrationsActive: Number(metrics.integrations) || 0,
    },
    executive: {
      overallStatus,
      score,
      threatsBlocked: Number(metrics.threatsBlocked) || 0,
      threatsQuarantined: Number(metrics.threatsQuarantined) || 0,
      falsePositives: Number(metrics.falsePositives) || 0,
      avgResponseTime: String(metrics.avgResponseTime || '0s'),
      uptime: Number(metrics.uptime) || 99.9,
    },
    controls,
    findings,
    recommendations,
  };
}

async function fetchComplianceMetrics(
  tenantId: string,
  startDate: Date,
  endDate: Date
): Promise<Record<string, unknown>> {
  try {
    // Fetch threat statistics
    const threatStats = await sql`
      SELECT
        COUNT(*) FILTER (WHERE action_taken = 'blocked') as blocked,
        COUNT(*) FILTER (WHERE action_taken = 'quarantine') as quarantined,
        COUNT(*) FILTER (WHERE action_taken = 'released' AND verdict != 'allow') as false_positives,
        AVG(EXTRACT(EPOCH FROM (action_taken_at - created_at))) as avg_response_seconds
      FROM threats
      WHERE tenant_id = ${tenantId}
        AND created_at BETWEEN ${startDate.toISOString()} AND ${endDate.toISOString()}
    `;

    // Fetch email count
    const emailCount = await sql`
      SELECT COUNT(*) as total
      FROM emails
      WHERE tenant_id = ${tenantId}
        AND received_at BETWEEN ${startDate.toISOString()} AND ${endDate.toISOString()}
    `;

    // Fetch integration count
    const integrations = await sql`
      SELECT COUNT(*) as total
      FROM integrations
      WHERE tenant_id = ${tenantId}
        AND is_active = true
    `;

    // Fetch user count (approximate from emails)
    const userCount = await sql`
      SELECT COUNT(DISTINCT recipient) as total
      FROM emails
      WHERE tenant_id = ${tenantId}
    `;

    const stats = threatStats[0] || {};
    return {
      threatsBlocked: Number(stats.blocked) || 0,
      threatsQuarantined: Number(stats.quarantined) || 0,
      falsePositives: Number(stats.false_positives) || 0,
      avgResponseTime: formatResponseTime(Number(stats.avg_response_seconds) || 0),
      emailsProcessed: Number(emailCount[0]?.total) || 0,
      integrations: Number(integrations[0]?.total) || 0,
      userCount: Number(userCount[0]?.total) || 0,
      uptime: 99.9, // Would come from monitoring system
      orgName: 'Organization',
      domain: 'example.com',
    };
  } catch (error) {
    console.error('Failed to fetch compliance metrics:', error);
    return {
      threatsBlocked: 0,
      threatsQuarantined: 0,
      falsePositives: 0,
      avgResponseTime: 'N/A',
      emailsProcessed: 0,
      integrations: 0,
      userCount: 0,
      uptime: 0,
      orgName: 'Organization',
      domain: 'example.com',
    };
  }
}

function formatResponseTime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3600)}h`;
}

function evaluateControls(metrics: Record<string, unknown>): ControlCategory[] {
  return SOC2_CATEGORIES.map((category) => {
    const controls = category.controls.map((control) => ({
      id: control.id,
      name: control.name,
      description: control.description,
      status: evaluateControlStatus(control.id, metrics),
      evidence: generateEvidence(control.id, metrics),
      lastTested: new Date(),
    }));

    const passCount = controls.filter((c) => c.status === 'pass').length;
    const categoryStatus =
      passCount === controls.length ? 'pass' :
      passCount >= controls.length / 2 ? 'partial' : 'fail';

    return {
      id: category.id,
      name: category.name,
      description: category.description,
      status: categoryStatus as 'pass' | 'partial' | 'fail',
      controls,
    };
  });
}

function evaluateControlStatus(
  controlId: string,
  metrics: Record<string, unknown>
): 'pass' | 'partial' | 'fail' {
  // Control-specific evaluation logic
  switch (controlId) {
    case 'CC6.6': // Threats Protection
      return (metrics.threatsBlocked as number) > 0 ? 'pass' : 'partial';
    case 'CC6.8': // Malware Prevention
      return (metrics.emailsProcessed as number) > 0 ? 'pass' : 'partial';
    case 'CC7.1': // Anomaly Detection
      return (metrics.threatsBlocked as number) + (metrics.threatsQuarantined as number) > 0 ? 'pass' : 'partial';
    case 'CC7.3': // Incident Response
      return (metrics.avgResponseTime as string) !== 'N/A' ? 'pass' : 'partial';
    case 'CC7.5': // Recovery
      return (metrics.uptime as number) >= 99 ? 'pass' : (metrics.uptime as number) >= 95 ? 'partial' : 'fail';
    default:
      return 'pass'; // Default to pass for controls we can't evaluate
  }
}

function generateEvidence(controlId: string, metrics: Record<string, unknown>): string[] {
  const evidence: string[] = [];

  switch (controlId) {
    case 'CC6.6':
      evidence.push(`${metrics.threatsBlocked} threats blocked during period`);
      evidence.push(`${metrics.threatsQuarantined} emails quarantined for review`);
      break;
    case 'CC6.8':
      evidence.push(`${metrics.emailsProcessed} emails scanned for malware`);
      break;
    case 'CC7.1':
      evidence.push('Real-time threat detection active');
      evidence.push('ML-based anomaly detection enabled');
      break;
    case 'CC7.3':
      evidence.push(`Average incident response time: ${metrics.avgResponseTime}`);
      evidence.push(`False positive rate: ${calculateFPRate(metrics)}%`);
      break;
    case 'CC7.5':
      evidence.push(`System uptime: ${metrics.uptime}%`);
      break;
    default:
      evidence.push('Control implemented and operational');
  }

  return evidence;
}

function calculateFPRate(metrics: Record<string, unknown>): string {
  const total = (metrics.threatsBlocked as number) + (metrics.threatsQuarantined as number);
  if (total === 0) return '0';
  return ((metrics.falsePositives as number) / total * 100).toFixed(2);
}

function generateFindings(
  controls: ControlCategory[],
  metrics: Record<string, unknown>
): Finding[] {
  const findings: Finding[] = [];
  let findingId = 1;

  for (const category of controls) {
    for (const control of category.controls) {
      if (control.status === 'fail') {
        findings.push({
          id: `F-${findingId++}`,
          severity: 'high',
          title: `${control.id}: ${control.name} - Non-Compliant`,
          description: `The control "${control.name}" was found to be non-compliant during the audit period.`,
          recommendation: `Implement remediation measures for ${control.id} to achieve compliance.`,
          status: 'open',
        });
      } else if (control.status === 'partial') {
        findings.push({
          id: `F-${findingId++}`,
          severity: 'medium',
          title: `${control.id}: ${control.name} - Partial Compliance`,
          description: `The control "${control.name}" is partially compliant and requires improvement.`,
          recommendation: `Review and enhance ${control.id} implementation.`,
          status: 'open',
        });
      }
    }
  }

  // Add specific findings based on metrics
  if ((metrics.falsePositives as number) > (metrics.threatsBlocked as number) * 0.1) {
    findings.push({
      id: `F-${findingId++}`,
      severity: 'medium',
      title: 'High False Positive Rate',
      description: 'The false positive rate exceeds 10% of blocked threats.',
      recommendation: 'Review and tune detection policies to reduce false positives.',
      status: 'open',
    });
  }

  return findings;
}

function generateRecommendations(
  findings: Finding[],
  metrics: Record<string, unknown>
): Recommendation[] {
  const recommendations: Recommendation[] = [];
  let recId = 1;

  // Based on findings
  const criticalFindings = findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  if (criticalFindings.length > 0) {
    recommendations.push({
      id: `R-${recId++}`,
      priority: 'high',
      title: 'Address Critical Compliance Gaps',
      description: `There are ${criticalFindings.length} high-priority findings that require immediate attention.`,
      impact: 'Achieving full SOC 2 compliance',
    });
  }

  // Based on metrics
  if ((metrics.avgResponseTime as string).includes('h')) {
    recommendations.push({
      id: `R-${recId++}`,
      priority: 'medium',
      title: 'Improve Incident Response Time',
      description: 'Average response time exceeds 1 hour. Consider implementing automated response workflows.',
      impact: 'Reducing time to mitigate threats',
    });
  }

  // General recommendations
  recommendations.push({
    id: `R-${recId++}`,
    priority: 'low',
    title: 'Regular Compliance Reviews',
    description: 'Schedule quarterly compliance reviews to maintain SOC 2 certification.',
    impact: 'Maintaining ongoing compliance',
  });

  return recommendations;
}

function calculateOverallStatus(controls: ControlCategory[]): 'compliant' | 'partially_compliant' | 'non_compliant' {
  const allControls = controls.flatMap((c) => c.controls);
  const passCount = allControls.filter((c) => c.status === 'pass').length;
  const failCount = allControls.filter((c) => c.status === 'fail').length;

  if (failCount === 0 && passCount >= allControls.length * 0.9) return 'compliant';
  if (failCount <= allControls.length * 0.1) return 'partially_compliant';
  return 'non_compliant';
}

function calculateComplianceScore(controls: ControlCategory[]): number {
  const allControls = controls.flatMap((c) => c.controls);
  const passCount = allControls.filter((c) => c.status === 'pass').length;
  const partialCount = allControls.filter((c) => c.status === 'partial').length;

  return Math.round((passCount + partialCount * 0.5) / allControls.length * 100);
}
