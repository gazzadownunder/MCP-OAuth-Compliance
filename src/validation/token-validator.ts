/**
 * JWT Access Token Validator
 *
 * Validates JWT access tokens according to:
 * - RFC 9068: JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
 * - MCP 2025-11-25: Token audience validation requirements
 */

import * as jose from 'jose';
import {
  JWTAccessTokenClaims,
  JWTAccessTokenClaimsSchema,
  validateAudience,
  isTokenExpired,
  isTokenNotYetValid,
  hasScope
} from '../types/token.js';
import { ProtocolVersion } from '../types/protocol-version.js';

export interface ValidationResult {
  compliant: boolean;
  errors: string[];
  warnings: string[];
  claims?: JWTAccessTokenClaims;
}

/**
 * JWT Access Token Validator
 * Validates tokens based on protocol version requirements
 */
export class TokenValidator {
  private protocolVersion: ProtocolVersion;

  constructor(protocolVersion: ProtocolVersion = ProtocolVersion.PRE_2025_11_25) {
    this.protocolVersion = protocolVersion;
  }

  /**
   * Decode and validate JWT access token structure (without signature verification)
   *
   * @param token - The JWT access token
   * @returns Validation result with decoded claims
   */
  async decodeAndValidate(token: string): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Decode JWT (without verification)
      const decoded = jose.decodeJwt(token);

      // Validate against schema
      const parseResult = JWTAccessTokenClaimsSchema.safeParse(decoded);

      if (!parseResult.success) {
        errors.push('Token claims do not match JWT Access Token schema');
        parseResult.error.errors.forEach(err => {
          errors.push(`${err.path.join('.')}: ${err.message}`);
        });
        // Return the decoded claims even if validation failed, so tests can show what's actually in the token
        return { compliant: false, errors, warnings, claims: decoded as any };
      }

      const claims = parseResult.data;

      // Validate expiration
      if (isTokenExpired(claims)) {
        errors.push('Token has expired');
      }

      // Validate not-before
      if (isTokenNotYetValid(claims)) {
        errors.push('Token is not yet valid (nbf claim in future)');
      }

      return {
        compliant: errors.length === 0,
        errors,
        warnings,
        claims
      };
    } catch (error) {
      errors.push(
        `Failed to decode JWT: ${error instanceof Error ? error.message : String(error)}`
      );
      return { compliant: false, errors, warnings };
    }
  }

  /**
   * Validate JWT access token with full signature verification
   *
   * @param token - The JWT access token
   * @param expectedAudience - Expected audience (MCP server URL for 2025-11-25)
   * @param expectedIssuer - Expected issuer (authorization server)
   * @param jwksUri - JWKS URI for signature verification
   * @returns Validation result
   */
  async validateAccessToken(
    token: string,
    expectedAudience: string,
    expectedIssuer: string,
    jwksUri: string
  ): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Step 1: Decode and validate structure
      const decodeResult = await this.decodeAndValidate(token);
      if (!decodeResult.compliant || !decodeResult.claims) {
        return decodeResult;
      }

      const claims = decodeResult.claims;
      errors.push(...decodeResult.errors);
      warnings.push(...decodeResult.warnings);

      // Step 2: Validate issuer
      if (claims.iss !== expectedIssuer) {
        errors.push(
          `Invalid issuer: expected "${expectedIssuer}", got "${claims.iss}"`
        );
      }

      // Step 3: Validate audience (REQUIRED for MCP 2025-11-25)
      if (this.protocolVersion === ProtocolVersion.MCP_2025_11_25) {
        if (!validateAudience(claims, expectedAudience)) {
          const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
          errors.push(
            `Token audience does not include expected resource: "${expectedAudience}". ` +
            `Found audiences: ${audiences.join(', ')}`
          );
        }

        // Check if resource claim matches (if present)
        if (claims.resource && claims.resource !== expectedAudience) {
          warnings.push(
            `Token resource claim ("${claims.resource}") does not match expected audience ("${expectedAudience}")`
          );
        }
      } else {
        // For pre-2025-11-25, audience validation is optional but recommended
        if (!validateAudience(claims, expectedAudience)) {
          warnings.push(
            `Token audience does not include expected resource: "${expectedAudience}". ` +
            'Audience validation is recommended for security.'
          );
        }
      }

      // Step 4: Verify signature
      try {
        const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));
        await jose.jwtVerify(token, JWKS, {
          issuer: expectedIssuer,
          // Only enforce audience in verification for 2025-11-25
          ...(this.protocolVersion === ProtocolVersion.MCP_2025_11_25 && {
            audience: expectedAudience
          })
        });
      } catch (error) {
        errors.push(
          `Token signature verification failed: ${error instanceof Error ? error.message : String(error)}`
        );
      }

      return {
        compliant: errors.length === 0,
        errors,
        warnings,
        claims
      };
    } catch (error) {
      errors.push(
        `Token validation failed: ${error instanceof Error ? error.message : String(error)}`
      );
      return { compliant: false, errors, warnings };
    }
  }

  /**
   * Validate token contains required scope
   *
   * @param token - JWT access token or claims
   * @param requiredScope - The scope to check for
   * @returns Validation result
   */
  async validateScope(
    token: string | JWTAccessTokenClaims,
    requiredScope: string
  ): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      let claims: JWTAccessTokenClaims;

      if (typeof token === 'string') {
        // Decode token
        const decodeResult = await this.decodeAndValidate(token);
        if (!decodeResult.compliant || !decodeResult.claims) {
          return decodeResult;
        }
        claims = decodeResult.claims;
      } else {
        claims = token;
      }

      // Check if scope claim exists
      if (!claims.scope) {
        warnings.push('Token does not contain scope claim');
        return { compliant: true, errors, warnings, claims }; // Not an error, just no scopes
      }

      // Check if required scope is present
      if (!hasScope(claims, requiredScope)) {
        errors.push(
          `Token does not have required scope: "${requiredScope}". ` +
          `Available scopes: ${claims.scope}`
        );
      }

      return {
        compliant: errors.length === 0,
        errors,
        warnings,
        claims
      };
    } catch (error) {
      errors.push(
        `Scope validation failed: ${error instanceof Error ? error.message : String(error)}`
      );
      return { compliant: false, errors, warnings };
    }
  }

  /**
   * Validate token resource claim (RFC 8707)
   *
   * @param token - JWT access token or claims
   * @param expectedResource - Expected resource URL
   * @returns Validation result
   */
  async validateResource(
    token: string | JWTAccessTokenClaims,
    expectedResource: string
  ): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      let claims: JWTAccessTokenClaims;

      if (typeof token === 'string') {
        const decodeResult = await this.decodeAndValidate(token);
        if (!decodeResult.compliant || !decodeResult.claims) {
          return decodeResult;
        }
        claims = decodeResult.claims;
      } else {
        claims = token;
      }

      // For MCP 2025-11-25, resource claim should be present
      if (this.protocolVersion === ProtocolVersion.MCP_2025_11_25) {
        if (!claims.resource) {
          warnings.push(
            'Token does not contain resource claim (RFC 8707). ' +
            'Resource parameter is required in MCP 2025-11-25.'
          );
        } else if (claims.resource !== expectedResource) {
          errors.push(
            `Token resource claim does not match expected value. ` +
            `Expected: "${expectedResource}", Got: "${claims.resource}"`
          );
        }
      } else {
        // For pre-2025-11-25, resource claim is optional
        if (claims.resource && claims.resource !== expectedResource) {
          warnings.push(
            `Token resource claim ("${claims.resource}") does not match expected resource ("${expectedResource}")`
          );
        }
      }

      return {
        compliant: errors.length === 0,
        errors,
        warnings,
        claims
      };
    } catch (error) {
      errors.push(
        `Resource validation failed: ${error instanceof Error ? error.message : String(error)}`
      );
      return { compliant: false, errors, warnings };
    }
  }

  /**
   * Extract header from JWT without validation
   *
   * @param token - JWT access token
   * @returns JWT header
   */
  decodeHeader(token: string): jose.ProtectedHeaderParameters {
    return jose.decodeProtectedHeader(token);
  }
}
