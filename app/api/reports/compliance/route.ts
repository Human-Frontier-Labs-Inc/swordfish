/**
 * Compliance Report API
 *
 * Generate SOC 2 and HIPAA compliance reports
 */

import { NextRequest, NextResponse } from 'next/server';
import { generateSOC2Report } from '@/lib/reports/compliance/soc2';
import { generateHIPAAReport } from '@/lib/reports/compliance/hipaa';
import { generateSOC2PDF, generateHIPAAPDF } from '@/lib/reports/pdf-generator';
import { getTenantId, Unauthorized } from '@/lib/auth/tenant';

export async function POST(request: NextRequest) {
  try {
    let tenantId: string;
    try {
      tenantId = await getTenantId();
    } catch (e) {
      if (e instanceof Unauthorized) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }
      throw e;
    }
    const body = await request.json();

    const {
      type,
      startDate,
      endDate,
      format = 'json',
    } = body as {
      type: 'soc2' | 'hipaa';
      startDate: string;
      endDate: string;
      format?: 'json' | 'pdf' | 'html';
    };

    // Validate inputs
    if (!type || !['soc2', 'hipaa'].includes(type)) {
      return NextResponse.json(
        { error: 'Invalid report type. Use "soc2" or "hipaa".' },
        { status: 400 }
      );
    }

    const start = new Date(startDate);
    const end = new Date(endDate);

    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return NextResponse.json(
        { error: 'Invalid date format' },
        { status: 400 }
      );
    }

    if (start >= end) {
      return NextResponse.json(
        { error: 'Start date must be before end date' },
        { status: 400 }
      );
    }

    // Generate and return report based on type
    if (type === 'soc2') {
      const soc2Report = await generateSOC2Report(tenantId, start, end);

      if (format === 'json') {
        return NextResponse.json({ report: soc2Report });
      }

      if (format === 'pdf' || format === 'html') {
        const pdf = await generateSOC2PDF(soc2Report);
        return new NextResponse(new Uint8Array(pdf.buffer), {
          headers: {
            'Content-Type': pdf.mimeType,
            'Content-Disposition': `attachment; filename="${pdf.filename}"`,
          },
        });
      }

      return NextResponse.json({ report: soc2Report });
    } else {
      const hipaaReport = await generateHIPAAReport(tenantId, start, end);

      if (format === 'json') {
        return NextResponse.json({ report: hipaaReport });
      }

      if (format === 'pdf' || format === 'html') {
        const pdf = await generateHIPAAPDF(hipaaReport);
        return new NextResponse(new Uint8Array(pdf.buffer), {
          headers: {
            'Content-Type': pdf.mimeType,
            'Content-Disposition': `attachment; filename="${pdf.filename}"`,
          },
        });
      }

      return NextResponse.json({ report: hipaaReport });
    }
  } catch (error) {
    console.error('Compliance report error:', error);
    return NextResponse.json(
      { error: 'Failed to generate report' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    try {
      await getTenantId();
    } catch (e) {
      if (e instanceof Unauthorized) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }
      throw e;
    }

    // Return available report types and options
    return NextResponse.json({
      availableReports: [
        {
          type: 'soc2',
          name: 'SOC 2 Type II',
          description: 'Service Organization Control 2 compliance report',
          categories: [
            'Control Environment',
            'Communication and Information',
            'Risk Assessment',
            'Logical and Physical Access',
            'System Operations',
          ],
        },
        {
          type: 'hipaa',
          name: 'HIPAA Security Rule',
          description: 'Health Insurance Portability and Accountability Act compliance report',
          categories: [
            'Administrative Safeguards',
            'Technical Safeguards',
            'PHI Protection',
          ],
        },
      ],
      formats: ['json', 'pdf', 'html'],
    });
  } catch (error) {
    console.error('Report types error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch report types' },
      { status: 500 }
    );
  }
}
