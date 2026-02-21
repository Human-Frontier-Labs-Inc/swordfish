/**
 * PDF Report Generator
 *
 * Generates PDF reports from compliance and security data
 * Uses HTML templates rendered to PDF
 */

import { SOC2ReportData } from './compliance/soc2';
import { HIPAAReportData } from './compliance/hipaa';

export type ReportType = 'soc2' | 'hipaa' | 'executive' | 'threats';

export interface PDFOptions {
  format?: 'A4' | 'Letter';
  orientation?: 'portrait' | 'landscape';
  margins?: {
    top: number;
    right: number;
    bottom: number;
    left: number;
  };
  headerHtml?: string;
  footerHtml?: string;
}

export interface GeneratedPDF {
  buffer: Buffer;
  filename: string;
  mimeType: string;
  pageCount: number;
}

/**
 * Generate PDF from SOC 2 report data
 */
export async function generateSOC2PDF(
  data: SOC2ReportData,
  options?: PDFOptions
): Promise<GeneratedPDF> {
  const html = renderSOC2ReportHTML(data);
  return generatePDFFromHTML(html, `soc2-report-${data.reportId}.pdf`, options);
}

/**
 * Generate PDF from HIPAA report data
 */
export async function generateHIPAAPDF(
  data: HIPAAReportData,
  options?: PDFOptions
): Promise<GeneratedPDF> {
  const html = renderHIPAAReportHTML(data);
  return generatePDFFromHTML(html, `hipaa-report-${data.reportId}.pdf`, options);
}

/**
 * Core PDF generation from HTML
 * Note: In production, use a service like Puppeteer, wkhtmltopdf, or a cloud service
 */
async function generatePDFFromHTML(
  html: string,
  filename: string,
  options?: PDFOptions
): Promise<GeneratedPDF> {
  // For serverless, we return HTML that can be rendered to PDF client-side
  // or use a PDF service API

  // Placeholder implementation - in production use:
  // 1. Puppeteer (if running on server with chromium)
  // 2. PDF service API (like html-pdf-service, pdf.co, etc.)
  // 3. Client-side rendering with jsPDF or similar

  const buffer = Buffer.from(html, 'utf-8');

  return {
    buffer,
    filename,
    mimeType: 'text/html', // Change to application/pdf when using real PDF generation
    pageCount: estimatePageCount(html),
  };
}

function estimatePageCount(html: string): number {
  // Rough estimate based on content length
  const charCount = html.replace(/<[^>]*>/g, '').length;
  return Math.ceil(charCount / 3000); // ~3000 chars per page
}

/**
 * Render SOC 2 Report as HTML
 */
function renderSOC2ReportHTML(data: SOC2ReportData): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SOC 2 Type II Compliance Report</title>
  <style>
    ${getReportStyles()}
  </style>
</head>
<body>
  <div class="report">
    <!-- Cover Page -->
    <div class="cover-page">
      <div class="logo">🔒</div>
      <h1>SOC 2 Type II</h1>
      <h2>Compliance Report</h2>
      <div class="org-name">${escapeHtml(data.organization.name)}</div>
      <div class="period">
        Audit Period: ${formatDate(data.period.start)} - ${formatDate(data.period.end)}
      </div>
      <div class="generated">Generated: ${formatDate(data.generatedAt)}</div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
      <h2>Executive Summary</h2>
      <div class="summary-grid">
        <div class="summary-card ${data.executive.overallStatus}">
          <div class="card-label">Overall Status</div>
          <div class="card-value">${formatStatus(data.executive.overallStatus)}</div>
        </div>
        <div class="summary-card">
          <div class="card-label">Compliance Score</div>
          <div class="card-value">${data.executive.score}%</div>
        </div>
        <div class="summary-card">
          <div class="card-label">Threats Blocked</div>
          <div class="card-value">${data.executive.threatsBlocked.toLocaleString()}</div>
        </div>
        <div class="summary-card">
          <div class="card-label">Avg Response Time</div>
          <div class="card-value">${data.executive.avgResponseTime}</div>
        </div>
      </div>

      <h3>Organization Overview</h3>
      <table class="info-table">
        <tr><td>Organization</td><td>${escapeHtml(data.organization.name)}</td></tr>
        <tr><td>Domain</td><td>${escapeHtml(data.organization.domain)}</td></tr>
        <tr><td>Users Protected</td><td>${data.organization.usersProtected.toLocaleString()}</td></tr>
        <tr><td>Emails Processed</td><td>${data.organization.emailsProcessed.toLocaleString()}</td></tr>
        <tr><td>Active Integrations</td><td>${data.organization.integrationsActive}</td></tr>
        <tr><td>System Uptime</td><td>${data.executive.uptime}%</td></tr>
      </table>
    </div>

    <!-- Controls Assessment -->
    <div class="section">
      <h2>Trust Services Criteria Assessment</h2>
      ${data.controls.map(category => `
        <div class="control-category">
          <h3>${category.id}: ${escapeHtml(category.name)}</h3>
          <p class="category-desc">${escapeHtml(category.description)}</p>
          <div class="category-status status-${category.status}">
            ${category.status.toUpperCase()}
          </div>

          <table class="controls-table">
            <thead>
              <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Status</th>
                <th>Last Tested</th>
              </tr>
            </thead>
            <tbody>
              ${category.controls.map(control => `
                <tr>
                  <td>${control.id}</td>
                  <td>${escapeHtml(control.name)}</td>
                  <td class="status-${control.status}">${control.status.toUpperCase()}</td>
                  <td>${formatDate(control.lastTested)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `).join('')}
    </div>

    <!-- Findings -->
    ${data.findings.length > 0 ? `
    <div class="section">
      <h2>Findings</h2>
      <table class="findings-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${data.findings.map(finding => `
            <tr>
              <td>${finding.id}</td>
              <td class="severity-${finding.severity}">${finding.severity.toUpperCase()}</td>
              <td>${escapeHtml(finding.title)}</td>
              <td>${finding.status}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>

      ${data.findings.map(finding => `
        <div class="finding-detail">
          <h4>${finding.id}: ${escapeHtml(finding.title)}</h4>
          <p><strong>Severity:</strong> ${finding.severity.toUpperCase()}</p>
          <p><strong>Description:</strong> ${escapeHtml(finding.description)}</p>
          <p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>
        </div>
      `).join('')}
    </div>
    ` : ''}

    <!-- Recommendations -->
    <div class="section">
      <h2>Recommendations</h2>
      ${data.recommendations.map(rec => `
        <div class="recommendation">
          <div class="rec-header">
            <span class="rec-id">${rec.id}</span>
            <span class="priority-${rec.priority}">${rec.priority.toUpperCase()}</span>
          </div>
          <h4>${escapeHtml(rec.title)}</h4>
          <p>${escapeHtml(rec.description)}</p>
          <p class="rec-impact"><strong>Impact:</strong> ${escapeHtml(rec.impact)}</p>
        </div>
      `).join('')}
    </div>

    <!-- Footer -->
    <div class="footer">
      <p>Report ID: ${data.reportId}</p>
      <p>This report was generated automatically by Swordfish Email Security Platform.</p>
      <p>Confidential - For authorized recipients only.</p>
    </div>
  </div>
</body>
</html>
  `;
}

/**
 * Render HIPAA Report as HTML
 */
function renderHIPAAReportHTML(data: HIPAAReportData): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>HIPAA Compliance Report</title>
  <style>
    ${getReportStyles()}
  </style>
</head>
<body>
  <div class="report">
    <!-- Cover Page -->
    <div class="cover-page">
      <div class="logo">🏥</div>
      <h1>HIPAA Security Rule</h1>
      <h2>Compliance Report</h2>
      <div class="org-name">${escapeHtml(data.organization.name)}</div>
      <div class="period">
        Assessment Period: ${formatDate(data.period.start)} - ${formatDate(data.period.end)}
      </div>
      <div class="generated">Generated: ${formatDate(data.generatedAt)}</div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
      <h2>Executive Summary</h2>
      <div class="summary-grid">
        <div class="summary-card ${data.executive.overallStatus}">
          <div class="card-label">Overall Status</div>
          <div class="card-value">${formatStatus(data.executive.overallStatus)}</div>
        </div>
        <div class="summary-card">
          <div class="card-label">Compliance Score</div>
          <div class="card-value">${data.executive.score}%</div>
        </div>
        <div class="summary-card">
          <div class="card-label">PHI Emails Protected</div>
          <div class="card-value">${data.executive.phiEmailsProtected.toLocaleString()}</div>
        </div>
        <div class="summary-card ${data.executive.phiBreachesDetected > 0 ? 'danger' : ''}">
          <div class="card-label">PHI Breaches</div>
          <div class="card-value">${data.executive.phiBreachesDetected}</div>
        </div>
      </div>

      <h3>PHI Protection Metrics</h3>
      <table class="info-table">
        <tr><td>Emails Scanned</td><td>${data.phiProtection.emailsScanned.toLocaleString()}</td></tr>
        <tr><td>PHI Detected</td><td>${data.phiProtection.phiDetected.toLocaleString()}</td></tr>
        <tr><td>PHI Protected</td><td>${data.phiProtection.phiProtected.toLocaleString()}</td></tr>
        <tr><td>PHI Blocked</td><td>${data.phiProtection.phiBlocked.toLocaleString()}</td></tr>
        <tr><td>Encryption Rate</td><td>${data.phiProtection.encryptionRate}%</td></tr>
      </table>
    </div>

    <!-- Safeguards Assessment -->
    <div class="section">
      <h2>HIPAA Security Safeguards</h2>
      ${data.safeguards.map(safeguard => `
        <div class="control-category">
          <h3>${escapeHtml(safeguard.name)}</h3>
          <p class="category-desc">${escapeHtml(safeguard.description)}</p>
          <p><strong>Type:</strong> ${safeguard.type}</p>
          <div class="category-status status-${safeguard.status}">
            ${safeguard.status.toUpperCase()}
          </div>

          <table class="controls-table">
            <thead>
              <tr>
                <th>Standard</th>
                <th>Requirement</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${safeguard.requirements.map(req => `
                <tr>
                  <td>${req.standard}</td>
                  <td>${escapeHtml(req.name)}</td>
                  <td class="status-${req.status}">${req.status.toUpperCase()}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `).join('')}
    </div>

    <!-- Findings -->
    ${data.findings.length > 0 ? `
    <div class="section">
      <h2>Compliance Findings</h2>
      ${data.findings.map(finding => `
        <div class="finding-detail severity-border-${finding.severity}">
          <h4>${finding.id}: ${escapeHtml(finding.title)}</h4>
          <p><strong>Category:</strong> ${escapeHtml(finding.category)}</p>
          <p><strong>Severity:</strong> <span class="severity-${finding.severity}">${finding.severity.toUpperCase()}</span></p>
          <p><strong>Description:</strong> ${escapeHtml(finding.description)}</p>
          <p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>
        </div>
      `).join('')}
    </div>
    ` : ''}

    <!-- Recommendations -->
    <div class="section">
      <h2>Recommendations</h2>
      ${data.recommendations.map(rec => `
        <div class="recommendation">
          <div class="rec-header">
            <span class="rec-id">${rec.id}</span>
            <span class="priority-${rec.priority}">${rec.priority.toUpperCase()}</span>
          </div>
          <h4>${escapeHtml(rec.title)}</h4>
          <p>${escapeHtml(rec.description)}</p>
          <p class="rec-ref"><strong>Regulatory Reference:</strong> ${escapeHtml(rec.regulatoryRef)}</p>
        </div>
      `).join('')}
    </div>

    <!-- Footer -->
    <div class="footer">
      <p>Report ID: ${data.reportId}</p>
      <p>This report was generated automatically by Swordfish Email Security Platform.</p>
      <p>Confidential - For authorized recipients only.</p>
    </div>
  </div>
</body>
</html>
  `;
}

/**
 * Common report styles
 */
function getReportStyles(): string {
  return `
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; }
    .report { max-width: 800px; margin: 0 auto; padding: 40px; }

    .cover-page {
      text-align: center;
      padding: 100px 0;
      page-break-after: always;
    }
    .cover-page .logo { font-size: 64px; margin-bottom: 20px; }
    .cover-page h1 { font-size: 36px; color: #1a365d; margin-bottom: 10px; }
    .cover-page h2 { font-size: 24px; color: #4a5568; margin-bottom: 40px; }
    .cover-page .org-name { font-size: 20px; font-weight: bold; margin-bottom: 20px; }
    .cover-page .period, .cover-page .generated { color: #718096; }

    .section { margin-bottom: 40px; page-break-inside: avoid; }
    .section h2 { font-size: 24px; color: #1a365d; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 20px; }
    .section h3 { font-size: 18px; color: #2d3748; margin: 20px 0 10px; }

    .summary-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-bottom: 30px; }
    .summary-card {
      background: #f7fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }
    .summary-card.compliant { background: #c6f6d5; border-color: #9ae6b4; }
    .summary-card.partially_compliant { background: #fefcbf; border-color: #f6e05e; }
    .summary-card.non_compliant, .summary-card.danger { background: #fed7d7; border-color: #fc8181; }
    .card-label { font-size: 12px; color: #718096; text-transform: uppercase; margin-bottom: 5px; }
    .card-value { font-size: 24px; font-weight: bold; color: #1a365d; }

    .info-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    .info-table td { padding: 10px; border-bottom: 1px solid #e2e8f0; }
    .info-table td:first-child { font-weight: 600; width: 40%; }

    .control-category { margin: 30px 0; padding: 20px; background: #f7fafc; border-radius: 8px; }
    .category-desc { color: #718096; margin-bottom: 10px; }
    .category-status { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .status-pass { background: #c6f6d5; color: #22543d; }
    .status-partial { background: #fefcbf; color: #744210; }
    .status-fail { background: #fed7d7; color: #742a2a; }

    .controls-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
    .controls-table th, .controls-table td { padding: 10px; text-align: left; border-bottom: 1px solid #e2e8f0; }
    .controls-table th { background: #edf2f7; font-weight: 600; }

    .findings-table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
    .findings-table th, .findings-table td { padding: 10px; text-align: left; border-bottom: 1px solid #e2e8f0; }
    .findings-table th { background: #edf2f7; }

    .finding-detail { margin: 20px 0; padding: 15px; background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; }
    .finding-detail h4 { color: #1a365d; margin-bottom: 10px; }
    .severity-border-critical { border-left: 4px solid #e53e3e; }
    .severity-border-high { border-left: 4px solid #ed8936; }
    .severity-border-medium { border-left: 4px solid #ecc94b; }
    .severity-border-low { border-left: 4px solid #4299e1; }

    .severity-critical { color: #e53e3e; font-weight: 600; }
    .severity-high { color: #ed8936; font-weight: 600; }
    .severity-medium { color: #ecc94b; font-weight: 600; }
    .severity-low { color: #4299e1; font-weight: 600; }

    .recommendation { margin: 20px 0; padding: 15px; background: #ebf8ff; border-radius: 8px; }
    .rec-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
    .rec-id { font-weight: 600; color: #2b6cb0; }
    .priority-high { background: #fed7d7; color: #742a2a; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
    .priority-medium { background: #fefcbf; color: #744210; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
    .priority-low { background: #c6f6d5; color: #22543d; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
    .recommendation h4 { color: #2b6cb0; margin-bottom: 10px; }
    .rec-impact, .rec-ref { color: #718096; margin-top: 10px; font-size: 14px; }

    .footer { margin-top: 60px; padding-top: 20px; border-top: 2px solid #e2e8f0; text-align: center; color: #718096; font-size: 12px; }
    .footer p { margin: 5px 0; }

    @media print {
      .report { padding: 20px; }
      .section { page-break-inside: avoid; }
      .cover-page { page-break-after: always; }
    }
  `;
}

// Helper functions
function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, (m) => map[m]);
}

function formatDate(date: Date | string): string {
  const d = new Date(date);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

function formatStatus(status: string): string {
  const map: Record<string, string> = {
    compliant: 'Compliant',
    partially_compliant: 'Partially Compliant',
    non_compliant: 'Non-Compliant',
  };
  return map[status] || status;
}
