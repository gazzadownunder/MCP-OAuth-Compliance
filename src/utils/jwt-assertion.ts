/**
 * JWT Assertion Builder for Private Key JWT Authentication (RFC 7523)
 *
 * Creates JWT assertions for client authentication at the token endpoint.
 * Requires client private keys for signing.
 */

import { webcrypto } from 'crypto';

/**
 * JWT Assertion Claims (RFC 7523 Section 3)
 */
export interface JWTAssertionClaims {
  /** Issuer - client_id */
  iss: string;
  /** Subject - client_id (must match iss) */
  sub: string;
  /** Audience - token endpoint URL */
  aud: string;
  /** Expiration time (Unix timestamp) */
  exp: number;
  /** JWT ID - unique identifier for this JWT */
  jti: string;
  /** Issued at time (Unix timestamp) - optional */
  iat?: number;
  /** Not before time (Unix timestamp) - optional */
  nbf?: number;
}

/**
 * JWT Header
 */
export interface JWTHeader {
  /** Algorithm - RS256, ES256, etc. */
  alg: string;
  /** Type - always "JWT" */
  typ: string;
  /** Key ID - identifies which key was used */
  kid?: string;
}

/**
 * Generate a JWT assertion for private_key_jwt authentication
 *
 * NOTE: This is a simplified implementation for testing purposes.
 * In production, use a proper JWT library like `jose` or `jsonwebtoken`.
 *
 * @param clientId - Client identifier (used for both iss and sub)
 * @param tokenEndpoint - Token endpoint URL (used for aud)
 * @param privateKey - Client private key (PEM format) - OPTIONAL for testing
 * @param kid - Key ID to include in header - OPTIONAL
 * @returns JWT assertion string
 */
export async function generateJWTAssertion(
  clientId: string,
  tokenEndpoint: string,
  privateKey?: string,
  kid?: string
): Promise<string> {
  // Generate JWT claims
  const now = Math.floor(Date.now() / 1000);
  const claims: JWTAssertionClaims = {
    iss: clientId,
    sub: clientId,
    aud: tokenEndpoint,
    exp: now + 300, // 5 minutes from now
    jti: generateJTI(),
    iat: now
  };

  // Generate JWT header
  const header: JWTHeader = {
    alg: 'RS256',
    typ: 'JWT'
  };

  if (kid) {
    header.kid = kid;
  }

  // Base64URL encode header and claims
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedClaims = base64UrlEncode(JSON.stringify(claims));

  const unsignedToken = `${encodedHeader}.${encodedClaims}`;

  // If no private key provided, return unsigned token for testing
  if (!privateKey) {
    // Return unsigned token with empty signature (for testing/validation only)
    return `${unsignedToken}.UNSIGNED_TEST_TOKEN`;
  }

  // Sign the token with private key
  // NOTE: Actual implementation would use proper crypto library
  // This is a placeholder for testing
  const signature = await signJWT(unsignedToken, privateKey);
  const encodedSignature = base64UrlEncode(signature);

  return `${unsignedToken}.${encodedSignature}`;
}

/**
 * Generate a unique JWT ID (jti)
 *
 * @returns Random UUID-like string
 */
function generateJTI(): string {
  // Generate random bytes and convert to hex
  const randomBytes = new Uint8Array(16);
  webcrypto.getRandomValues(randomBytes);

  const hex = Array.from(randomBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // Format as UUID
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Base64 URL encode a string
 *
 * @param str - String to encode
 * @returns Base64 URL encoded string
 */
function base64UrlEncode(str: string): string {
  const base64 = Buffer.from(str).toString('base64');
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Sign JWT with private key
 *
 * NOTE: This is a placeholder implementation.
 * In production, use a proper JWT library.
 *
 * @param data - Data to sign (header.payload)
 * @param privateKey - Private key in PEM format
 * @returns Signature bytes
 */
async function signJWT(data: string, _privateKey: string): Promise<string> {
  // This is a simplified placeholder
  // In production, you would:
  // 1. Parse the PEM private key
  // 2. Use crypto.subtle.sign() or a library like 'jose'
  // 3. Return the actual signature

  // For now, return a placeholder signature
  return `PLACEHOLDER_SIGNATURE_${data.length}`;
}

/**
 * Validate JWT assertion format (without signature verification)
 *
 * @param assertion - JWT assertion string
 * @returns Validation result with parsed claims
 */
export function validateJWTAssertionFormat(assertion: string): {
  valid: boolean;
  header?: JWTHeader;
  claims?: JWTAssertionClaims;
  errors: string[];
} {
  const errors: string[] = [];

  // Split JWT into parts
  const parts = assertion.split('.');
  if (parts.length !== 3) {
    errors.push('JWT must have exactly 3 parts (header.payload.signature)');
    return { valid: false, errors };
  }

  try {
    // Decode header
    const headerJson = Buffer.from(parts[0], 'base64').toString('utf-8');
    const header = JSON.parse(headerJson) as JWTHeader;

    // Validate header
    if (!header.alg) {
      errors.push('Header missing required "alg" field');
    }
    if (header.typ !== 'JWT') {
      errors.push('Header "typ" must be "JWT"');
    }

    // Decode claims
    const claimsJson = Buffer.from(parts[1], 'base64').toString('utf-8');
    const claims = JSON.parse(claimsJson) as JWTAssertionClaims;

    // Validate required claims
    if (!claims.iss) errors.push('Missing required claim: iss');
    if (!claims.sub) errors.push('Missing required claim: sub');
    if (!claims.aud) errors.push('Missing required claim: aud');
    if (!claims.exp) errors.push('Missing required claim: exp');
    if (!claims.jti) errors.push('Missing required claim: jti');

    // Validate iss and sub match
    if (claims.iss !== claims.sub) {
      errors.push('Claims iss and sub must be equal (both should be client_id)');
    }

    // Validate exp is in the future
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp <= now) {
      errors.push('Claim exp (expiration) must be in the future');
    }

    return {
      valid: errors.length === 0,
      header,
      claims,
      errors
    };
  } catch (error: any) {
    errors.push(`Failed to parse JWT: ${error.message}`);
    return { valid: false, errors };
  }
}
