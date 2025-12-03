/**
 * JWT Access Token Types for MCP OAuth
 *
 * This module defines token claim schemas and validation
 * for JWT access tokens following RFC 9068 and MCP 2025-11-25 requirements.
 */

import { z } from 'zod';

/**
 * JWT Access Token Claims (RFC 9068)
 * Enhanced with MCP 2025-11-25 requirements
 *
 * @see https://www.rfc-editor.org/rfc/rfc9068
 */
export const JWTAccessTokenClaimsSchema = z.object({
  // Standard JWT claims (RFC 7519)
  /**
   * Issuer - MUST be the authorization server issuer URL
   */
  iss: z.string().url({
    message: 'Issuer (iss) must be a valid URL'
  }),

  /**
   * Subject - identifier for the principal (user)
   */
  sub: z.string().min(1, {
    message: 'Subject (sub) is required'
  }),

  /**
   * Audience - REQUIRED for MCP 2025-11-25
   * Can be a single string or array of strings
   * MUST include the resource server (MCP server URL)
   */
  aud: z.union([
    z.string(),
    z.array(z.string())
  ]).refine(
    (aud) => {
      const audiences = Array.isArray(aud) ? aud : [aud];
      return audiences.length > 0 && audiences.every(a => a.length > 0);
    },
    {
      message: 'Audience (aud) must be non-empty'
    }
  ),

  /**
   * Expiration time - Unix timestamp
   */
  exp: z.number().int().positive({
    message: 'Expiration time (exp) must be a positive integer'
  }),

  /**
   * Issued at - Unix timestamp
   */
  iat: z.number().int().nonnegative({
    message: 'Issued at (iat) must be a non-negative integer'
  }),

  /**
   * Not before - Unix timestamp (optional)
   */
  nbf: z.number().int().nonnegative().optional(),

  /**
   * JWT ID - unique identifier (optional)
   */
  jti: z.string().optional(),

  // OAuth 2.0 claims
  /**
   * Client ID - the OAuth client identifier
   */
  client_id: z.string().min(1, {
    message: 'Client ID is required'
  }),

  /**
   * Scope - space-separated list of scopes
   */
  scope: z.string().optional(),

  // RFC 8707 Resource Indicator (NEW in MCP 2025-11-25)
  /**
   * Resource - the protected resource (MCP server URL)
   * REQUIRED in MCP 2025-11-25
   *
   * @see https://www.rfc-editor.org/rfc/rfc8707
   */
  resource: z.string().url().optional()
}).passthrough(); // Allow additional claims

/**
 * Inferred TypeScript type from the schema
 */
export type JWTAccessTokenClaims = z.infer<typeof JWTAccessTokenClaimsSchema>;

/**
 * OAuth 2.0 Token Response (RFC 6749)
 */
export const TokenResponseSchema = z.object({
  /**
   * The access token issued by the authorization server
   */
  access_token: z.string().min(1),

  /**
   * The type of token (typically "Bearer")
   */
  token_type: z.string().default('Bearer'),

  /**
   * Token lifetime in seconds (optional)
   */
  expires_in: z.number().int().positive().optional(),

  /**
   * Refresh token (optional)
   */
  refresh_token: z.string().optional(),

  /**
   * Scope of the access token (optional)
   * If omitted, same as requested scope
   */
  scope: z.string().optional(),

  /**
   * Resource indicators (RFC 8707) - optional
   * List of resources this token is valid for
   */
  resource: z.union([
    z.string().url(),
    z.array(z.string().url())
  ]).optional()
}).passthrough();

/**
 * Inferred TypeScript type from the schema
 */
export type TokenResponse = z.infer<typeof TokenResponseSchema>;

/**
 * Token Error Response (RFC 6749 Section 5.2)
 */
export const TokenErrorResponseSchema = z.object({
  /**
   * Error code
   */
  error: z.enum([
    'invalid_request',
    'invalid_client',
    'invalid_grant',
    'unauthorized_client',
    'unsupported_grant_type',
    'invalid_scope'
  ]),

  /**
   * Human-readable error description (optional)
   */
  error_description: z.string().optional(),

  /**
   * URI to error documentation (optional)
   */
  error_uri: z.string().url().optional()
}).passthrough();

/**
 * Inferred TypeScript type from the schema
 */
export type TokenErrorResponse = z.infer<typeof TokenErrorResponseSchema>;

/**
 * Validate token audience matches expected resource
 *
 * @param claims - JWT access token claims
 * @param expectedResource - Expected resource URL (MCP server)
 * @returns true if audience includes the expected resource
 */
export function validateAudience(
  claims: JWTAccessTokenClaims,
  expectedResource: string
): boolean {
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  return audiences.includes(expectedResource);
}

/**
 * Check if token is expired
 *
 * @param claims - JWT access token claims
 * @param clockSkewSeconds - Allow for clock skew (default: 60 seconds)
 * @returns true if token is expired
 */
export function isTokenExpired(
  claims: JWTAccessTokenClaims,
  clockSkewSeconds: number = 60
): boolean {
  const now = Math.floor(Date.now() / 1000);
  return claims.exp < (now - clockSkewSeconds);
}

/**
 * Check if token is not yet valid (nbf check)
 *
 * @param claims - JWT access token claims
 * @param clockSkewSeconds - Allow for clock skew (default: 60 seconds)
 * @returns true if token is not yet valid
 */
export function isTokenNotYetValid(
  claims: JWTAccessTokenClaims,
  clockSkewSeconds: number = 60
): boolean {
  if (!claims.nbf) {
    return false;
  }
  const now = Math.floor(Date.now() / 1000);
  return claims.nbf > (now + clockSkewSeconds);
}

/**
 * Parse scope string into array of individual scopes
 *
 * @param scope - Space-separated scope string
 * @returns Array of scope values
 */
export function parseScopes(scope?: string): string[] {
  if (!scope) {
    return [];
  }
  return scope.split(' ').filter(s => s.length > 0);
}

/**
 * Check if token has a specific scope
 *
 * @param claims - JWT access token claims
 * @param requiredScope - The scope to check for
 * @returns true if token has the required scope
 */
export function hasScope(
  claims: JWTAccessTokenClaims,
  requiredScope: string
): boolean {
  const scopes = parseScopes(claims.scope);
  return scopes.includes(requiredScope);
}
