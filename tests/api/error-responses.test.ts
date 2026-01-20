/**
 * Error Response Standardization Tests
 * TDD: Consistent API error responses following RFC 7807
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  ApiError,
  createErrorResponse,
  errorToResponse,
  isApiError,
  ErrorCode,
  HttpStatus,
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  InternalError,
  ServiceUnavailableError,
} from '@/lib/api/errors';

describe('Error Response Standardization', () => {
  describe('ApiError', () => {
    it('should create error with required fields', () => {
      const error = new ApiError('Something went wrong', 400, 'BAD_REQUEST');

      expect(error.message).toBe('Something went wrong');
      expect(error.statusCode).toBe(400);
      expect(error.code).toBe('BAD_REQUEST');
    });

    it('should be an Error instance', () => {
      const error = new ApiError('Test', 400, 'TEST');

      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe('ApiError');
    });

    it('should support optional details', () => {
      const error = new ApiError('Validation failed', 400, 'VALIDATION_ERROR', {
        fields: [
          { field: 'email', message: 'Invalid format' },
          { field: 'name', message: 'Required' },
        ],
      });

      expect(error.details).toBeDefined();
      expect(error.details?.fields).toHaveLength(2);
    });

    it('should support optional instance ID', () => {
      const error = new ApiError('Not found', 404, 'NOT_FOUND', undefined, '/api/users/123');

      expect(error.instance).toBe('/api/users/123');
    });

    it('should serialize to JSON correctly', () => {
      const error = new ApiError('Test error', 400, 'TEST_ERROR', { extra: 'data' });
      const json = error.toJSON();

      expect(json).toEqual({
        type: 'about:blank',
        title: 'Test error',
        status: 400,
        detail: 'Test error',
        code: 'TEST_ERROR',
        extra: 'data',
      });
    });

    it('should support RFC 7807 Problem Details format', () => {
      const error = new ApiError('Resource not found', 404, 'RESOURCE_NOT_FOUND');
      const json = error.toJSON();

      // RFC 7807 required fields
      expect(json).toHaveProperty('type');
      expect(json).toHaveProperty('title');
      expect(json).toHaveProperty('status');
    });
  });

  describe('Error Helper Classes', () => {
    describe('BadRequestError', () => {
      it('should have status 400', () => {
        const error = new BadRequestError('Invalid input');

        expect(error.statusCode).toBe(400);
        expect(error.code).toBe('BAD_REQUEST');
      });

      it('should support validation errors', () => {
        const error = new BadRequestError('Validation failed', [
          { field: 'email', message: 'Invalid email format' },
        ]);

        expect(error.details?.fields).toHaveLength(1);
      });
    });

    describe('UnauthorizedError', () => {
      it('should have status 401', () => {
        const error = new UnauthorizedError();

        expect(error.statusCode).toBe(401);
        expect(error.code).toBe('UNAUTHORIZED');
        expect(error.message).toBe('Authentication required');
      });

      it('should support custom message', () => {
        const error = new UnauthorizedError('Invalid token');

        expect(error.message).toBe('Invalid token');
      });
    });

    describe('ForbiddenError', () => {
      it('should have status 403', () => {
        const error = new ForbiddenError();

        expect(error.statusCode).toBe(403);
        expect(error.code).toBe('FORBIDDEN');
      });
    });

    describe('NotFoundError', () => {
      it('should have status 404', () => {
        const error = new NotFoundError('User not found');

        expect(error.statusCode).toBe(404);
        expect(error.code).toBe('NOT_FOUND');
      });

      it('should support resource type', () => {
        const error = new NotFoundError('Threat not found', 'threat');

        expect(error.details?.resourceType).toBe('threat');
      });
    });

    describe('ConflictError', () => {
      it('should have status 409', () => {
        const error = new ConflictError('Resource already exists');

        expect(error.statusCode).toBe(409);
        expect(error.code).toBe('CONFLICT');
      });
    });

    describe('RateLimitError', () => {
      it('should have status 429', () => {
        const error = new RateLimitError(60);

        expect(error.statusCode).toBe(429);
        expect(error.code).toBe('RATE_LIMITED');
      });

      it('should include retryAfter', () => {
        const error = new RateLimitError(30);

        expect(error.details?.retryAfter).toBe(30);
      });
    });

    describe('InternalError', () => {
      it('should have status 500', () => {
        const error = new InternalError();

        expect(error.statusCode).toBe(500);
        expect(error.code).toBe('INTERNAL_ERROR');
      });

      it('should hide sensitive details in production', () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';

        const error = new InternalError('Database connection failed');
        const json = error.toJSON();

        // In production, don't leak internal details
        expect(json.detail).toBe('An unexpected error occurred');

        process.env.NODE_ENV = originalEnv;
      });
    });

    describe('ServiceUnavailableError', () => {
      it('should have status 503', () => {
        const error = new ServiceUnavailableError();

        expect(error.statusCode).toBe(503);
        expect(error.code).toBe('SERVICE_UNAVAILABLE');
      });
    });
  });

  describe('createErrorResponse', () => {
    it('should create Response with correct status', () => {
      const response = createErrorResponse(new ApiError('Test', 400, 'TEST'));

      expect(response.status).toBe(400);
    });

    it('should set Content-Type header', () => {
      const response = createErrorResponse(new ApiError('Test', 400, 'TEST'));

      expect(response.headers.get('Content-Type')).toBe('application/problem+json');
    });

    it('should include error body as JSON', async () => {
      const response = createErrorResponse(new NotFoundError('User not found'));
      const body = await response.json();

      expect(body.status).toBe(404);
      expect(body.code).toBe('NOT_FOUND');
    });
  });

  describe('errorToResponse', () => {
    it('should convert ApiError to Response', () => {
      const error = new BadRequestError('Invalid input');
      const response = errorToResponse(error);

      expect(response.status).toBe(400);
    });

    it('should convert unknown Error to 500 Response', () => {
      const error = new Error('Something broke');
      const response = errorToResponse(error);

      expect(response.status).toBe(500);
    });

    it('should convert ZodError to 400 Response', () => {
      // Simulate a Zod validation error structure
      const zodError = {
        name: 'ZodError',
        errors: [
          { path: ['email'], message: 'Invalid email' },
          { path: ['name'], message: 'Too short' },
        ],
        message: 'Validation failed',
      };

      const response = errorToResponse(zodError);

      expect(response.status).toBe(400);
    });

    it('should handle null/undefined gracefully', () => {
      const response = errorToResponse(null);

      expect(response.status).toBe(500);
    });
  });

  describe('isApiError', () => {
    it('should return true for ApiError', () => {
      const error = new ApiError('Test', 400, 'TEST');

      expect(isApiError(error)).toBe(true);
    });

    it('should return true for ApiError subclasses', () => {
      expect(isApiError(new BadRequestError('Test'))).toBe(true);
      expect(isApiError(new NotFoundError('Test'))).toBe(true);
      expect(isApiError(new InternalError())).toBe(true);
    });

    it('should return false for regular Error', () => {
      const error = new Error('Test');

      expect(isApiError(error)).toBe(false);
    });

    it('should return false for non-errors', () => {
      expect(isApiError(null)).toBe(false);
      expect(isApiError(undefined)).toBe(false);
      expect(isApiError('string')).toBe(false);
      expect(isApiError({})).toBe(false);
    });
  });

  describe('ErrorCode', () => {
    it('should have standard error codes', () => {
      expect(ErrorCode.BAD_REQUEST).toBe('BAD_REQUEST');
      expect(ErrorCode.UNAUTHORIZED).toBe('UNAUTHORIZED');
      expect(ErrorCode.FORBIDDEN).toBe('FORBIDDEN');
      expect(ErrorCode.NOT_FOUND).toBe('NOT_FOUND');
      expect(ErrorCode.CONFLICT).toBe('CONFLICT');
      expect(ErrorCode.RATE_LIMITED).toBe('RATE_LIMITED');
      expect(ErrorCode.INTERNAL_ERROR).toBe('INTERNAL_ERROR');
      expect(ErrorCode.SERVICE_UNAVAILABLE).toBe('SERVICE_UNAVAILABLE');
    });

    it('should have validation error code', () => {
      expect(ErrorCode.VALIDATION_ERROR).toBe('VALIDATION_ERROR');
    });
  });

  describe('HttpStatus', () => {
    it('should have standard HTTP status codes', () => {
      expect(HttpStatus.OK).toBe(200);
      expect(HttpStatus.CREATED).toBe(201);
      expect(HttpStatus.NO_CONTENT).toBe(204);
      expect(HttpStatus.BAD_REQUEST).toBe(400);
      expect(HttpStatus.UNAUTHORIZED).toBe(401);
      expect(HttpStatus.FORBIDDEN).toBe(403);
      expect(HttpStatus.NOT_FOUND).toBe(404);
      expect(HttpStatus.CONFLICT).toBe(409);
      expect(HttpStatus.TOO_MANY_REQUESTS).toBe(429);
      expect(HttpStatus.INTERNAL_SERVER_ERROR).toBe(500);
      expect(HttpStatus.SERVICE_UNAVAILABLE).toBe(503);
    });
  });

  describe('Error chaining', () => {
    it('should preserve original error cause', () => {
      const originalError = new Error('Database timeout');
      const apiError = new InternalError('Failed to fetch data');
      (apiError as Error & { cause?: Error }).cause = originalError;

      expect((apiError as Error & { cause?: Error }).cause).toBe(originalError);
    });
  });

  describe('Request ID in errors', () => {
    it('should support request ID for tracing', () => {
      const error = new ApiError('Test', 400, 'TEST');
      error.requestId = 'req_abc123';

      const json = error.toJSON();

      expect(json.requestId).toBe('req_abc123');
    });
  });
});
