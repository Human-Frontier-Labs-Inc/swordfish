'use client';

/**
 * API Documentation Page
 * Interactive API reference for Swordfish
 */

import { useState } from 'react';

interface Endpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  description: string;
  auth: boolean;
  params?: Array<{
    name: string;
    type: string;
    required: boolean;
    description: string;
  }>;
  body?: {
    type: string;
    example: object;
  };
  response?: {
    type: string;
    example: object;
  };
}

interface ApiSection {
  name: string;
  description: string;
  endpoints: Endpoint[];
}

const API_SECTIONS: ApiSection[] = [
  {
    name: 'Threats',
    description: 'Manage quarantined threats and security incidents',
    endpoints: [
      {
        method: 'GET',
        path: '/api/threats',
        description: 'List all threats for the tenant',
        auth: true,
        params: [
          { name: 'status', type: 'string', required: false, description: 'Filter by status: quarantined, released, deleted, all' },
          { name: 'limit', type: 'number', required: false, description: 'Max results (default: 50)' },
          { name: 'offset', type: 'number', required: false, description: 'Pagination offset' },
          { name: 'stats', type: 'boolean', required: false, description: 'Include statistics' },
        ],
        response: {
          type: 'object',
          example: {
            threats: [{ id: 'uuid', subject: 'Suspicious email', score: 85 }],
            stats: { quarantinedCount: 10, last24Hours: 3 },
            pagination: { limit: 50, offset: 0, hasMore: false },
          },
        },
      },
      {
        method: 'GET',
        path: '/api/threats/search',
        description: 'Advanced threat search with filters',
        auth: true,
        params: [
          { name: 'q', type: 'string', required: false, description: 'Free text search query' },
          { name: 'status', type: 'string', required: false, description: 'Comma-separated statuses' },
          { name: 'scoreMin', type: 'number', required: false, description: 'Minimum threat score' },
          { name: 'scoreMax', type: 'number', required: false, description: 'Maximum threat score' },
          { name: 'from', type: 'string', required: false, description: 'Start date (ISO format)' },
          { name: 'to', type: 'string', required: false, description: 'End date (ISO format)' },
          { name: 'sortBy', type: 'string', required: false, description: 'Sort field: date, score, sender' },
        ],
        response: {
          type: 'object',
          example: {
            threats: [],
            pagination: { page: 1, limit: 25, total: 0, totalPages: 0 },
            aggregations: { statuses: [], verdicts: [] },
          },
        },
      },
      {
        method: 'POST',
        path: '/api/threats/search',
        description: 'Advanced search with complex filters',
        auth: true,
        body: {
          type: 'SearchFilters',
          example: {
            query: 'invoice',
            status: ['quarantined'],
            senderDomains: ['suspicious.com'],
            scoreMin: 60,
            dateFrom: '2024-01-01',
            sortBy: 'score',
            sortOrder: 'desc',
          },
        },
      },
      {
        method: 'GET',
        path: '/api/threats/[id]',
        description: 'Get threat details by ID',
        auth: true,
        response: {
          type: 'object',
          example: {
            threat: {
              id: 'uuid',
              subject: 'Urgent: Wire Transfer',
              senderEmail: 'attacker@phishing.com',
              score: 92,
              status: 'quarantined',
              signals: [],
            },
          },
        },
      },
      {
        method: 'POST',
        path: '/api/threats/[id]/release',
        description: 'Release threat from quarantine',
        auth: true,
        response: {
          type: 'object',
          example: { success: true },
        },
      },
      {
        method: 'DELETE',
        path: '/api/threats/[id]',
        description: 'Permanently delete quarantined threat',
        auth: true,
      },
      {
        method: 'GET',
        path: '/api/threats/feed',
        description: 'Real-time threat feed (polling or SSE)',
        auth: true,
        params: [
          { name: 'mode', type: 'string', required: false, description: 'poll (default) or stream for SSE' },
          { name: 'since', type: 'string', required: false, description: 'ISO timestamp for incremental updates' },
          { name: 'limit', type: 'number', required: false, description: 'Max threats (default: 20)' },
        ],
      },
    ],
  },
  {
    name: 'Quarantine',
    description: 'Manage quarantined emails',
    endpoints: [
      {
        method: 'GET',
        path: '/api/quarantine',
        description: 'List quarantined emails',
        auth: true,
        params: [
          { name: 'page', type: 'number', required: false, description: 'Page number' },
          { name: 'limit', type: 'number', required: false, description: 'Results per page' },
        ],
      },
      {
        method: 'GET',
        path: '/api/quarantine/[id]',
        description: 'Get quarantined email details',
        auth: true,
      },
      {
        method: 'POST',
        path: '/api/quarantine/[id]/release',
        description: 'Release email from quarantine to inbox',
        auth: true,
      },
      {
        method: 'DELETE',
        path: '/api/quarantine/[id]',
        description: 'Permanently delete quarantined email',
        auth: true,
      },
    ],
  },
  {
    name: 'Feedback',
    description: 'Submit and manage verdict feedback',
    endpoints: [
      {
        method: 'GET',
        path: '/api/feedback',
        description: 'List all feedback submissions',
        auth: true,
        params: [
          { name: 'page', type: 'number', required: false, description: 'Page number' },
          { name: 'limit', type: 'number', required: false, description: 'Results per page' },
          { name: 'type', type: 'string', required: false, description: 'Filter by feedback type' },
        ],
      },
      {
        method: 'POST',
        path: '/api/feedback',
        description: 'Submit feedback for an email',
        auth: true,
        body: {
          type: 'FeedbackRequest',
          example: {
            messageId: 'message-uuid',
            feedbackType: 'false_positive',
            notes: 'This is a legitimate email from our vendor',
            correctedVerdict: 'pass',
          },
        },
      },
      {
        method: 'POST',
        path: '/api/threats/[id]/feedback',
        description: 'Submit feedback for a specific threat',
        auth: true,
        body: {
          type: 'FeedbackRequest',
          example: {
            feedbackType: 'false_positive',
            notes: 'Known sender',
          },
        },
      },
    ],
  },
  {
    name: 'Analytics',
    description: 'Dashboard statistics and analytics',
    endpoints: [
      {
        method: 'GET',
        path: '/api/analytics',
        description: 'Get comprehensive dashboard analytics',
        auth: true,
        params: [
          { name: 'days', type: 'number', required: false, description: 'Days to analyze (default: 7)' },
        ],
        response: {
          type: 'DashboardStats',
          example: {
            summary: { totalEmails: 1000, threatsBlocked: 50, quarantined: 20, passRate: 95 },
            trends: { emailsToday: 100, threatsToday: 5 },
            verdictBreakdown: { pass: 900, suspicious: 50, quarantine: 40, block: 10 },
          },
        },
      },
      {
        method: 'GET',
        path: '/api/analytics/timeseries',
        description: 'Get time series data for charts',
        auth: true,
        params: [
          { name: 'type', type: 'string', required: false, description: 'emails, threats, scores, hourly' },
          { name: 'days', type: 'number', required: false, description: 'Days to analyze' },
        ],
      },
      {
        method: 'GET',
        path: '/api/analytics/performance',
        description: 'Get detection performance metrics',
        auth: true,
        response: {
          type: 'object',
          example: {
            performance: { avgLatency: 150, p95Latency: 300, llmUsageRate: 15 },
            policyEffectiveness: { allowlistHits: 50, blocklistHits: 200 },
            topSenders: [],
            topDomains: [],
          },
        },
      },
      {
        method: 'GET',
        path: '/api/stats',
        description: 'Real-time dashboard statistics',
        auth: true,
        params: [
          { name: 'period', type: 'string', required: false, description: '24h, 7d, 30d, 90d' },
        ],
      },
    ],
  },
  {
    name: 'Policies',
    description: 'Manage allow/block lists and rules',
    endpoints: [
      {
        method: 'GET',
        path: '/api/policies',
        description: 'List all policies',
        auth: true,
        params: [
          { name: 'type', type: 'string', required: false, description: 'allowlist, blocklist, rule' },
        ],
      },
      {
        method: 'POST',
        path: '/api/policies',
        description: 'Create a new policy',
        auth: true,
        body: {
          type: 'PolicyCreate',
          example: {
            type: 'allowlist',
            target: 'domain',
            value: 'trusted-vendor.com',
            action: 'allow',
          },
        },
      },
      {
        method: 'PUT',
        path: '/api/policies/[id]',
        description: 'Update an existing policy',
        auth: true,
      },
      {
        method: 'DELETE',
        path: '/api/policies/[id]',
        description: 'Delete a policy',
        auth: true,
      },
    ],
  },
  {
    name: 'Integrations',
    description: 'Manage email provider integrations',
    endpoints: [
      {
        method: 'GET',
        path: '/api/integrations',
        description: 'List configured integrations',
        auth: true,
      },
      {
        method: 'POST',
        path: '/api/integrations/[provider]/connect',
        description: 'Start OAuth flow for provider (o365, gmail)',
        auth: true,
      },
      {
        method: 'DELETE',
        path: '/api/integrations/[provider]',
        description: 'Disconnect integration',
        auth: true,
      },
      {
        method: 'POST',
        path: '/api/sync',
        description: 'Trigger manual email sync',
        auth: true,
      },
    ],
  },
  {
    name: 'Reports',
    description: 'Generate and export reports',
    endpoints: [
      {
        method: 'GET',
        path: '/api/reports',
        description: 'List available reports',
        auth: true,
      },
      {
        method: 'POST',
        path: '/api/reports/generate',
        description: 'Generate a new report',
        auth: true,
        body: {
          type: 'ReportRequest',
          example: {
            type: 'executive_summary',
            dateRange: { start: '2024-01-01', end: '2024-01-31' },
            format: 'pdf',
          },
        },
      },
    ],
  },
];

const methodColors = {
  GET: 'bg-green-100 text-green-800',
  POST: 'bg-blue-100 text-blue-800',
  PUT: 'bg-yellow-100 text-yellow-800',
  DELETE: 'bg-red-100 text-red-800',
};

export default function ApiDocsPage() {
  const [selectedSection, setSelectedSection] = useState<string | null>(null);
  const [expandedEndpoint, setExpandedEndpoint] = useState<string | null>(null);

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">API Documentation</h1>
          <p className="mt-2 text-gray-600">
            Complete reference for the Swordfish Email Security API
          </p>
        </div>

        {/* Authentication Info */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-8">
          <h2 className="text-lg font-semibold text-blue-900">Authentication</h2>
          <p className="text-blue-800 mt-1">
            All API endpoints require authentication via Clerk session cookies.
            API calls are automatically scoped to your organization (tenant).
          </p>
        </div>

        {/* Base URL */}
        <div className="bg-white border rounded-lg p-4 mb-8">
          <h3 className="text-sm font-medium text-gray-500">Base URL</h3>
          <code className="text-lg font-mono text-gray-900">
            {typeof window !== 'undefined' ? window.location.origin : 'https://your-domain.com'}
          </code>
        </div>

        {/* API Sections */}
        <div className="space-y-6">
          {API_SECTIONS.map((section) => (
            <div key={section.name} className="bg-white border rounded-lg overflow-hidden">
              <button
                onClick={() => setSelectedSection(selectedSection === section.name ? null : section.name)}
                className="w-full px-6 py-4 text-left flex items-center justify-between hover:bg-gray-50"
              >
                <div>
                  <h2 className="text-xl font-semibold text-gray-900">{section.name}</h2>
                  <p className="text-sm text-gray-500">{section.description}</p>
                </div>
                <svg
                  className={`w-5 h-5 text-gray-500 transition-transform ${
                    selectedSection === section.name ? 'rotate-180' : ''
                  }`}
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {selectedSection === section.name && (
                <div className="border-t divide-y">
                  {section.endpoints.map((endpoint, idx) => (
                    <div key={idx} className="px-6 py-4">
                      <button
                        onClick={() =>
                          setExpandedEndpoint(
                            expandedEndpoint === `${section.name}-${idx}`
                              ? null
                              : `${section.name}-${idx}`
                          )
                        }
                        className="w-full text-left"
                      >
                        <div className="flex items-center gap-3">
                          <span
                            className={`px-2 py-1 text-xs font-medium rounded ${
                              methodColors[endpoint.method]
                            }`}
                          >
                            {endpoint.method}
                          </span>
                          <code className="text-sm font-mono text-gray-800">
                            {endpoint.path}
                          </code>
                        </div>
                        <p className="text-sm text-gray-600 mt-1">{endpoint.description}</p>
                      </button>

                      {expandedEndpoint === `${section.name}-${idx}` && (
                        <div className="mt-4 space-y-4">
                          {endpoint.params && endpoint.params.length > 0 && (
                            <div>
                              <h4 className="text-sm font-medium text-gray-700 mb-2">
                                Query Parameters
                              </h4>
                              <div className="bg-gray-50 rounded p-3 space-y-2">
                                {endpoint.params.map((param) => (
                                  <div key={param.name} className="text-sm">
                                    <code className="text-blue-600">{param.name}</code>
                                    <span className="text-gray-500 ml-2">({param.type})</span>
                                    {param.required && (
                                      <span className="text-red-500 ml-1">*</span>
                                    )}
                                    <span className="text-gray-600 ml-2">{param.description}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {endpoint.body && (
                            <div>
                              <h4 className="text-sm font-medium text-gray-700 mb-2">
                                Request Body ({endpoint.body.type})
                              </h4>
                              <pre className="bg-gray-900 text-green-400 rounded p-3 text-sm overflow-auto">
                                {JSON.stringify(endpoint.body.example, null, 2)}
                              </pre>
                            </div>
                          )}

                          {endpoint.response && (
                            <div>
                              <h4 className="text-sm font-medium text-gray-700 mb-2">
                                Response ({endpoint.response.type})
                              </h4>
                              <pre className="bg-gray-900 text-green-400 rounded p-3 text-sm overflow-auto">
                                {JSON.stringify(endpoint.response.example, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Feedback Types Reference */}
        <div className="mt-8 bg-white border rounded-lg p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Feedback Types</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { type: 'false_positive', desc: 'Legitimate email marked as threat' },
              { type: 'false_negative', desc: 'Threat that was not detected' },
              { type: 'confirmed_threat', desc: 'Confirm detection was correct' },
              { type: 'spam', desc: 'Unwanted commercial email' },
              { type: 'phishing', desc: 'Credential theft attempt' },
              { type: 'malware', desc: 'Malicious attachment/link' },
              { type: 'other', desc: 'Other feedback' },
            ].map((fb) => (
              <div key={fb.type} className="p-3 bg-gray-50 rounded">
                <code className="text-sm text-blue-600">{fb.type}</code>
                <p className="text-xs text-gray-600 mt-1">{fb.desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Status Codes */}
        <div className="mt-8 bg-white border rounded-lg p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Status Codes</h2>
          <div className="space-y-2">
            {[
              { code: 200, desc: 'Success' },
              { code: 201, desc: 'Created' },
              { code: 400, desc: 'Bad Request - Invalid parameters' },
              { code: 401, desc: 'Unauthorized - Authentication required' },
              { code: 403, desc: 'Forbidden - Insufficient permissions' },
              { code: 404, desc: 'Not Found - Resource does not exist' },
              { code: 500, desc: 'Internal Server Error' },
            ].map((status) => (
              <div key={status.code} className="flex items-center gap-4">
                <span
                  className={`px-2 py-1 text-sm font-mono rounded ${
                    status.code < 300
                      ? 'bg-green-100 text-green-800'
                      : status.code < 500
                      ? 'bg-yellow-100 text-yellow-800'
                      : 'bg-red-100 text-red-800'
                  }`}
                >
                  {status.code}
                </span>
                <span className="text-gray-600">{status.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
