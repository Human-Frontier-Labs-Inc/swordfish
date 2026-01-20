/**
 * API Error Response Module
 *
 * Standardized error responses following RFC 7807 Problem Details.
 * Provides consistent error handling across all API endpoints.
 */

/**
 * Standard HTTP status codes
 */
export const HttpStatus = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  SERVICE_UNAVAILABLE: 503,
} as const;

/**
 * Standard error codes
 */
export const ErrorCode = {
  BAD_REQUEST: 'BAD_REQUEST',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  RATE_LIMITED: 'RATE_LIMITED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
} as const;

/**
 * Error detail structure for validation errors
 */
export interface FieldError {
  field: string;
  message: string;
}

/**
 * RFC 7807 Problem Details JSON response
 */
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  code: string;
  instance?: string;
  requestId?: string;
  [key: string]: unknown;
}

/**
 * Base API Error class
 *
 * Follows RFC 7807 Problem Details for HTTP APIs
 */
export class ApiError extends Error {
  statusCode: number;
  code: string;
  details?: Record<string, unknown>;
  instance?: string;
  requestId?: string;

  constructor(
    message: string,
    statusCode: number,
    code: string,
    details?: Record<string, unknown>,
    instance?: string
  ) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.instance = instance;
  }

  /**
   * Serialize to RFC 7807 Problem Details JSON
   */
  toJSON(): ProblemDetails {
    const json: ProblemDetails = {
      type: 'about:blank',
      title: this.message,
      status: this.statusCode,
      detail: this.message,
      code: this.code,
    };

    if (this.instance) {
      json.instance = this.instance;
    }

    if (this.requestId) {
      json.requestId = this.requestId;
    }

    // Spread additional details
    if (this.details) {
      Object.assign(json, this.details);
    }

    return json;
  }
}

/**
 * 400 Bad Request
 */
export class BadRequestError extends ApiError {
  constructor(message = 'Bad request', fields?: FieldError[]) {
    super(
      message,
      HttpStatus.BAD_REQUEST,
      ErrorCode.BAD_REQUEST,
      fields ? { fields } : undefined
    );
    this.name = 'BadRequestError';
  }
}

/**
 * 401 Unauthorized
 */
export class UnauthorizedError extends ApiError {
  constructor(message = 'Authentication required') {
    super(message, HttpStatus.UNAUTHORIZED, ErrorCode.UNAUTHORIZED);
    this.name = 'UnauthorizedError';
  }
}

/**
 * 403 Forbidden
 */
export class ForbiddenError extends ApiError {
  constructor(message = 'Access denied') {
    super(message, HttpStatus.FORBIDDEN, ErrorCode.FORBIDDEN);
    this.name = 'ForbiddenError';
  }
}

/**
 * 404 Not Found
 */
export class NotFoundError extends ApiError {
  constructor(message = 'Resource not found', resourceType?: string) {
    super(
      message,
      HttpStatus.NOT_FOUND,
      ErrorCode.NOT_FOUND,
      resourceType ? { resourceType } : undefined
    );
    this.name = 'NotFoundError';
  }
}

/**
 * 409 Conflict
 */
export class ConflictError extends ApiError {
  constructor(message = 'Resource conflict') {
    super(message, HttpStatus.CONFLICT, ErrorCode.CONFLICT);
    this.name = 'ConflictError';
  }
}

/**
 * 429 Rate Limited
 */
export class RateLimitError extends ApiError {
  constructor(retryAfter: number, message = 'Rate limit exceeded') {
    super(message, HttpStatus.TOO_MANY_REQUESTS, ErrorCode.RATE_LIMITED, { retryAfter });
    this.name = 'RateLimitError';
  }
}

/**
 * 500 Internal Server Error
 *
 * In production, hides internal details from the response.
 */
export class InternalError extends ApiError {
  private internalMessage: string;

  constructor(message = 'An unexpected error occurred') {
    const isProduction = process.env.NODE_ENV === 'production';
    const publicMessage = isProduction ? 'An unexpected error occurred' : message;

    super(publicMessage, HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_ERROR);
    this.name = 'InternalError';
    this.internalMessage = message;
  }

  /**
   * Get the internal message (for logging)
   */
  getInternalMessage(): string {
    return this.internalMessage;
  }
}

/**
 * 503 Service Unavailable
 */
export class ServiceUnavailableError extends ApiError {
  constructor(message = 'Service temporarily unavailable') {
    super(message, HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SERVICE_UNAVAILABLE);
    this.name = 'ServiceUnavailableError';
  }
}

/**
 * Check if an error is an ApiError
 */
export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

/**
 * Create a Response from an ApiError
 */
export function createErrorResponse(error: ApiError): Response {
  return new Response(JSON.stringify(error.toJSON()), {
    status: error.statusCode,
    headers: {
      'Content-Type': 'application/problem+json',
    },
  });
}

/**
 * Convert any error to an API Response
 *
 * Handles ApiError, ZodError, and generic Error types.
 */
export function errorToResponse(error: unknown): Response {
  // Handle null/undefined
  if (error === null || error === undefined) {
    return createErrorResponse(new InternalError('Unknown error'));
  }

  // Handle ApiError
  if (isApiError(error)) {
    return createErrorResponse(error);
  }

  // Handle ZodError (validation)
  if (isZodError(error)) {
    const fields = error.errors.map((e: { path: (string | number)[]; message: string }) => ({
      field: e.path.join('.'),
      message: e.message,
    }));
    return createErrorResponse(new BadRequestError('Validation failed', fields));
  }

  // Handle generic Error
  if (error instanceof Error) {
    return createErrorResponse(new InternalError(error.message));
  }

  // Unknown error type
  return createErrorResponse(new InternalError('Unknown error'));
}

/**
 * Check if error looks like a ZodError
 */
function isZodError(
  error: unknown
): error is { name: string; errors: Array<{ path: (string | number)[]; message: string }> } {
  return (
    typeof error === 'object' &&
    error !== null &&
    'name' in error &&
    error.name === 'ZodError' &&
    'errors' in error &&
    Array.isArray(error.errors)
  );
}

/**
 * Wrap an async handler with error handling
 */
export function withErrorHandling<T extends unknown[], R>(
  handler: (...args: T) => Promise<R | Response>
): (...args: T) => Promise<R | Response> {
  return async (...args: T) => {
    try {
      return await handler(...args);
    } catch (error) {
      return errorToResponse(error);
    }
  };
}
