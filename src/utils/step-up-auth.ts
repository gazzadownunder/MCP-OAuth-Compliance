/**
 * Step-Up Authorization Handler
 *
 * Handles step-up authorization flows for MCP 2025-11-25.
 * Step-up authorization allows clients to re-authorize with additional scopes
 * when they encounter insufficient_scope errors.
 *
 * @see MCP 2025-11-25 Specification Section 10.1
 */

import { AuthorizationRequestParams } from './oauth-flow.js';

/**
 * Insufficient scope error response
 */
export interface InsufficientScopeError {
  /** Error code (should be 'insufficient_scope') */
  error: string;
  /** Human-readable error description */
  error_description?: string;
  /** URI to error documentation */
  error_uri?: string;
  /** Required scope(s) */
  scope?: string;
  /** HTTP status code */
  status?: number;
  /** WWW-Authenticate header value */
  wwwAuthenticate?: string;
}

/**
 * Authorization result from step-up flow
 */
export interface AuthorizationResult {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  scope?: string;
  error?: string;
}

/**
 * Step-Up Authorization Handler
 *
 * Manages the step-up authorization flow when clients need additional scopes.
 */
export class StepUpAuthHandler {
  private retryCount: number = 0;
  private maxRetries: number = 3;
  private attemptedScopes: Set<string> = new Set();

  constructor(maxRetries: number = 3) {
    this.maxRetries = maxRetries;
  }

  /**
   * Detect if error response indicates insufficient scope
   *
   * @param error - Error response from MCP server or resource server
   * @returns true if error indicates insufficient scope
   */
  detectInsufficientScope(error: any): boolean {
    // Check error code
    if (error.error === 'insufficient_scope') {
      return true;
    }

    // Check HTTP status (403 Forbidden typically indicates insufficient scope)
    if (error.status === 403 || error.statusCode === 403) {
      return true;
    }

    // Check WWW-Authenticate header
    if (error.headers?.['www-authenticate']) {
      const wwwAuth = error.headers['www-authenticate'];
      if (typeof wwwAuth === 'string' && wwwAuth.includes('insufficient_scope')) {
        return true;
      }
    }

    // Check response body
    if (error.body?.error === 'insufficient_scope') {
      return true;
    }

    return false;
  }

  /**
   * Parse required scopes from error response
   *
   * Attempts to extract scope information from:
   * 1. `scope` field in error response body
   * 2. `error_description` field (parsing text)
   * 3. WWW-Authenticate header
   *
   * @param error - Error response
   * @returns Array of required scopes
   */
  parseRequiredScopes(error: InsufficientScopeError | any): string[] {
    const scopes: string[] = [];

    // Method 1: Direct scope field in response body
    if (error.scope) {
      scopes.push(...this.parseScopeString(error.scope));
    }

    if (error.body?.scope) {
      scopes.push(...this.parseScopeString(error.body.scope));
    }

    // Method 2: Parse from error_description
    if (error.error_description) {
      const parsedScopes = this.extractScopesFromDescription(error.error_description);
      scopes.push(...parsedScopes);
    }

    if (error.body?.error_description) {
      const parsedScopes = this.extractScopesFromDescription(error.body.error_description);
      scopes.push(...parsedScopes);
    }

    // Method 3: Parse WWW-Authenticate header
    const wwwAuth = error.wwwAuthenticate || error.headers?.['www-authenticate'];
    if (wwwAuth) {
      const parsedScopes = this.parseScopesFromWWWAuthenticate(wwwAuth);
      scopes.push(...parsedScopes);
    }

    // Remove duplicates and return
    return [...new Set(scopes)];
  }

  /**
   * Initiate re-authorization with additional scopes
   *
   * @param currentScopes - Current scopes array
   * @param requiredScopes - Required scopes array
   * @param authParams - Original authorization parameters
   * @returns Updated authorization parameters with combined scopes
   */
  prepareReauthorization(
    currentScopes: string[],
    requiredScopes: string[],
    authParams: AuthorizationRequestParams
  ): AuthorizationRequestParams {
    // Combine current and required scopes
    const allScopes = [...new Set([...currentScopes, ...requiredScopes])];
    const scopeString = allScopes.join(' ');

    // Track attempted scopes to prevent infinite loops
    this.attemptedScopes.add(scopeString);

    // Return updated auth params with new scope
    return {
      ...authParams,
      scope: scopeString
    };
  }

  /**
   * Increment retry count and check if retry is allowed
   *
   * @returns Current retry count
   */
  incrementRetryCount(): number {
    this.retryCount++;
    return this.retryCount;
  }

  /**
   * Check if retry is allowed
   *
   * @returns true if retry count is within limit
   */
  canRetry(): boolean {
    return this.retryCount < this.maxRetries;
  }

  /**
   * Check if scope combination has already been attempted
   *
   * @param scopes - Array of scopes to check
   * @returns true if this scope combination was already tried
   */
  hasAttemptedScopes(scopes: string[]): boolean {
    const scopeString = [...scopes].sort().join(' ');
    return this.attemptedScopes.has(scopeString);
  }

  /**
   * Reset retry state
   */
  reset(): void {
    this.retryCount = 0;
    this.attemptedScopes.clear();
  }

  /**
   * Get current retry count
   */
  getRetryCount(): number {
    return this.retryCount;
  }

  /**
   * Get max retries allowed
   */
  getMaxRetries(): number {
    return this.maxRetries;
  }

  /**
   * Parse scope string into array
   *
   * @param scopeString - Space-separated scope string
   * @returns Array of individual scopes
   */
  private parseScopeString(scopeString: string): string[] {
    if (!scopeString) {
      return [];
    }
    return scopeString.split(/\s+/).filter(s => s.length > 0);
  }

  /**
   * Extract scopes from error description text
   *
   * Looks for patterns like:
   * - "requires the 'admin' scope"
   * - "scope: admin"
   * - "scopes required: admin, user"
   *
   * @param description - Error description text
   * @returns Array of extracted scopes
   */
  private extractScopesFromDescription(description: string): string[] {
    const scopes: string[] = [];

    // Pattern 1: "scope: admin" or "scopes: admin user"
    const pattern1 = /scopes?[:\s]+([a-z_\s,]+)/i;
    const match1 = description.match(pattern1);
    if (match1) {
      const scopeText = match1[1].replace(/,/g, ' ');
      scopes.push(...this.parseScopeString(scopeText));
    }

    // Pattern 2: "requires the 'admin' scope"
    const pattern2 = /['"]([a-z_]+)['"]\s+scope/i;
    const match2 = description.match(pattern2);
    if (match2) {
      scopes.push(match2[1]);
    }

    // Pattern 3: "requires scope 'admin'"
    const pattern3 = /scope\s+['"]([a-z_]+)['"]/i;
    const match3 = description.match(pattern3);
    if (match3) {
      scopes.push(match3[1]);
    }

    return scopes;
  }

  /**
   * Parse scopes from WWW-Authenticate header
   *
   * Format: Bearer error="insufficient_scope", scope="admin user"
   *
   * @param wwwAuthHeader - WWW-Authenticate header value
   * @returns Array of scopes
   */
  private parseScopesFromWWWAuthenticate(wwwAuthHeader: string): string[] {
    const scopes: string[] = [];

    // Extract scope parameter
    const scopeMatch = wwwAuthHeader.match(/scope="([^"]+)"/);
    if (scopeMatch) {
      scopes.push(...this.parseScopeString(scopeMatch[1]));
    }

    return scopes;
  }
}

/**
 * Create an InsufficientScopeError from an HTTP error response
 *
 * @param status - HTTP status code
 * @param body - Response body
 * @param headers - Response headers
 * @returns InsufficientScopeError object
 */
export function createInsufficientScopeError(
  status: number,
  body: any,
  headers?: Record<string, string>
): InsufficientScopeError {
  return {
    error: body?.error || 'insufficient_scope',
    error_description: body?.error_description,
    error_uri: body?.error_uri,
    scope: body?.scope,
    status,
    wwwAuthenticate: headers?.['www-authenticate']
  };
}
