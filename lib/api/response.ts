/**
 * API Response Helpers
 *
 * Standardized API response format for REST API v1
 */

import { NextResponse } from 'next/server';

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  meta?: {
    page?: number;
    pageSize?: number;
    total?: number;
    totalPages?: number;
  };
}

export interface PaginationParams {
  page: number;
  pageSize: number;
  offset: number;
}

/**
 * Parse pagination parameters from request
 */
export function parsePagination(
  searchParams: URLSearchParams,
  maxPageSize: number = 100
): PaginationParams {
  const parsedPage = parseInt(searchParams.get('page') || '1');
  const parsedPageSize = parseInt(searchParams.get('pageSize') || '20');

  const page = Math.max(1, isNaN(parsedPage) ? 1 : parsedPage);
  const pageSize = Math.min(maxPageSize, Math.max(1, isNaN(parsedPageSize) ? 20 : parsedPageSize));
  const offset = (page - 1) * pageSize;

  return { page, pageSize, offset };
}

/**
 * Create a successful response
 */
export function apiSuccess<T>(
  data: T,
  meta?: ApiResponse['meta'],
  headers?: Record<string, string>
): NextResponse {
  const response: ApiResponse<T> = {
    success: true,
    data,
  };

  if (meta) {
    response.meta = meta;
  }

  return NextResponse.json(response, {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}

/**
 * Create a created response (201)
 */
export function apiCreated<T>(
  data: T,
  headers?: Record<string, string>
): NextResponse {
  return NextResponse.json(
    { success: true, data },
    {
      status: 201,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    }
  );
}

/**
 * Create an error response
 */
export function apiError(
  code: string,
  message: string,
  status: number = 400,
  details?: unknown,
  headers?: Record<string, string>
): NextResponse {
  const response: ApiResponse = {
    success: false,
    error: {
      code,
      message,
    },
  };

  if (details) {
    response.error!.details = details;
  }

  return NextResponse.json(response, {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}

// Common error responses
export const errors = {
  unauthorized: (message = 'Unauthorized') =>
    apiError('UNAUTHORIZED', message, 401),

  forbidden: (message = 'Forbidden') =>
    apiError('FORBIDDEN', message, 403),

  notFound: (resource = 'Resource') =>
    apiError('NOT_FOUND', `${resource} not found`, 404),

  badRequest: (message: string, details?: unknown) =>
    apiError('BAD_REQUEST', message, 400, details),

  conflict: (message: string) =>
    apiError('CONFLICT', message, 409),

  rateLimited: (retryAfter: number) =>
    apiError('RATE_LIMITED', `Rate limit exceeded. Retry after ${retryAfter} seconds.`, 429),

  serverError: (message = 'Internal server error') =>
    apiError('SERVER_ERROR', message, 500),

  invalidScope: (required: string) =>
    apiError('INVALID_SCOPE', `Required scope: ${required}`, 403),
};

/**
 * Wrap an API handler with standard error handling
 */
export function withErrorHandling(
  handler: () => Promise<NextResponse>
): Promise<NextResponse> {
  return handler().catch((error) => {
    console.error('API Error:', error);
    return errors.serverError(
      process.env.NODE_ENV === 'development' ? error.message : undefined
    );
  });
}
