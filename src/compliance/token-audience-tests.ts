/**
 * Token Audience Validation Tests (MCP 2025-11-25)
 *
 * Tests JWT access token audience validation as required by MCP 2025-11-25.
 * Ensures tokens contain the correct audience (aud) claim matching the resource server.
 */

import {
  ComplianceTestResult,
  ComplianceCategory,
  ServerTestConfig
} from '../types/compliance.js';
import { ProtocolVersion } from '../types/protocol-version.js';
import { TokenValidator } from '../validation/token-validator.js';
import { JWTAccessTokenClaims, validateAudience } from '../types/token.js';

/**
 * Run token audience validation tests
 *
 * @param config - Test configuration
 * @param authServerUrl - Authorization server URL (from cache)
 * @param accessToken - JWT access token to validate (optional)
 * @returns Test results
 */
export async function runTokenAudienceTests(
  config: ServerTestConfig,
  authServerUrl: string | undefined,
  accessToken?: string
): Promise<ComplianceTestResult[]> {
  const results: ComplianceTestResult[] = [];
  const protocolVersion = config.protocolVersion || ProtocolVersion.PRE_2025_11_25;
  const validator = new TokenValidator(protocolVersion);

  // Header
  results.push({
    id: 'audience-header',
    category: ComplianceCategory.TOKEN_AUDIENCE,
    requirement: 'Token Audience Validation',
    status: 'info',
    message: `Protocol version: ${protocolVersion}`,
    timestamp: new Date(),
    indentLevel: 0
  });

  // For pre-2025-11-25, audience validation is optional
  if (protocolVersion !== ProtocolVersion.MCP_2025_11_25) {
    results.push({
      id: 'audience-1',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Audience validation',
      status: 'skip',
      message: 'Audience validation is optional for pre-2025-11-25 (recommended but not required)',
      timestamp: new Date(),
      indentLevel: 1
    });
    return results;
  }

  // Check if we have an access token to validate
  if (!accessToken) {
    results.push({
      id: 'audience-1',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Access token available',
      status: 'skip',
      message: 'No access token provided for validation',
      timestamp: new Date(),
      indentLevel: 1
    });
    return results;
  }

  // Get expected audience (resource server URL)
  const expectedAudience = config.resourceParameter || config.serverUrl;

  if (!expectedAudience) {
    results.push({
      id: 'audience-2',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Expected audience configured',
      status: 'fail',
      message: 'Cannot validate audience - resource URL not configured',
      timestamp: new Date(),
      indentLevel: 1,
      remediation: 'Configure serverUrl or resourceParameter in test config'
    });
    return results;
  }

  // Test 1: Decode and validate token structure
  const decodeResult = await validator.decodeAndValidate(accessToken);

  // Extract missing required claims from validation errors
  const requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat', 'client_id'];
  const presentClaims = decodeResult.claims ? Object.keys(decodeResult.claims) : [];
  const missingRequired = requiredClaims.filter(claim => !presentClaims.includes(claim));

  // Build actual message - show what's missing, not the full token
  let actualMessage = '';
  if (decodeResult.claims) {
    if (missingRequired.length > 0) {
      actualMessage = `Missing required claims: ${missingRequired.join(', ')}`;
    } else {
      actualMessage = 'All required claims present';
    }
  } else {
    actualMessage = 'Failed to decode token';
  }

  results.push({
    id: 'audience-1',
    category: ComplianceCategory.TOKEN_AUDIENCE,
    requirement: 'Token structure validation',
    status: decodeResult.compliant ? 'pass' : 'fail',
    message: decodeResult.compliant
      ? 'Token structure is valid'
      : `Validation errors: ${decodeResult.errors.join(', ')}`,
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 9068 Section 2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9068#section-2',
    expected: 'Valid JWT Access Token with required claims: iss, exp, aud, sub, client_id, iat, jti',
    actual: actualMessage,
    details: {
      validationResults: {
        compliant: decodeResult.compliant,
        errors: decodeResult.errors,
        warnings: decodeResult.warnings
      },
      decodedClaims: decodeResult.claims,
      presentClaims,
      missingRequiredClaims: missingRequired,
      recommendedClaims: ['jti', 'scope'].filter(claim => !presentClaims.includes(claim)),
      tokenPreview: `${accessToken.substring(0, 30)}...${accessToken.substring(accessToken.length - 30)}`
    }
  });

  if (!decodeResult.compliant || !decodeResult.claims) {
    return results;
  }

  const claims = decodeResult.claims;

  // Test 2: Audience claim exists
  const hasAudienceClaim = !!claims.aud;

  results.push({
    id: 'audience-2',
    category: ComplianceCategory.TOKEN_AUDIENCE,
    requirement: 'Token contains audience (aud) claim',
    status: hasAudienceClaim ? 'pass' : 'fail',
    message: hasAudienceClaim
      ? `Audience claim present: ${Array.isArray(claims.aud) ? claims.aud.join(', ') : claims.aud}`
      : 'Audience (aud) claim is missing (REQUIRED for MCP 2025-11-25)',
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 9068 Section 2.2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9068#section-2.2',
    expected: 'Non-empty aud claim (string or array of strings)',
    actual: hasAudienceClaim
      ? `${Array.isArray(claims.aud) ? `[${claims.aud.map(a => `"${a}"`).join(', ')}]` : `"${claims.aud}"`}`
      : 'undefined (claim not present in token)',
    details: {
      audClaim: claims.aud,
      audType: Array.isArray(claims.aud) ? 'array' : typeof claims.aud,
      allClaims: Object.keys(claims)
    }
  });

  if (!hasAudienceClaim) {
    return results;
  }

  // Test 3: Audience matches expected resource
  const audienceMatches = validateAudience(claims, expectedAudience);

  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];

  results.push({
    id: 'audience-3',
    category: ComplianceCategory.TOKEN_AUDIENCE,
    requirement: 'Audience matches resource server (REQUIRED)',
    status: audienceMatches ? 'pass' : 'fail',
    message: audienceMatches
      ? `Audience correctly includes resource: ${expectedAudience}`
      : `Token audience does not include expected resource: ${expectedAudience}`,
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'MCP 2025-11-25 Specification',
    expected: `Token aud claim must include resource server URL: "${expectedAudience}"`,
    actual: `Token aud claim: ${Array.isArray(claims.aud) ? `[${audiences.map(a => `"${a}"`).join(', ')}]` : `"${claims.aud}"`}`,
    details: {
      expectedAudience,
      actualAudiences: audiences,
      audienceType: Array.isArray(claims.aud) ? 'array' : 'string',
      matches: audienceMatches,
      comparison: audiences.map(aud => ({
        audience: aud,
        matchesExpected: aud === expectedAudience
      }))
    },
    remediation: audienceMatches
      ? undefined
      : 'Ensure the authorization server includes the resource parameter value in the token audience (aud) claim.\n\nThe aud claim should contain the resource server URL that was sent in the resource parameter during authorization and token requests.'
  });

  // Test 4: Resource claim validation (if present)
  if (claims.resource) {
    const resourceMatches = claims.resource === expectedAudience;

    results.push({
      id: 'audience-4',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Resource claim matches expected value',
      status: resourceMatches ? 'pass' : 'warning',
      message: resourceMatches
        ? `Resource claim correctly set: ${claims.resource}`
        : `Resource claim mismatch: expected ${expectedAudience}, got ${claims.resource}`,
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 8707 Section 3',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707#section-3',
      expected: `resource: "${expectedAudience}"`,
      actual: `resource: "${claims.resource}"`,
      details: {
        expectedResource: expectedAudience,
        actualResource: claims.resource,
        matches: resourceMatches,
        note: 'The resource claim is optional but recommended per RFC 8707'
      }
    });
  } else {
    results.push({
      id: 'audience-4',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Resource claim present',
      status: 'info',
      message: 'Token does not contain resource claim (optional per RFC 8707)',
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 8707 Section 3',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707#section-3',
      details: {
        expectedResource: expectedAudience,
        actualResource: undefined,
        note: 'The resource claim is optional. The aud claim is sufficient for audience validation.',
        presentClaims: Object.keys(claims)
      }
    });
  }

  // Test 5: Token expiration
  const isExpired = decodeResult.claims ? isTokenExpired(decodeResult.claims) : true;
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = new Date(claims.exp * 1000);
  const issuedAt = claims.iat ? new Date(claims.iat * 1000) : undefined;
  const timeRemaining = claims.exp - now;

  results.push({
    id: 'audience-5',
    category: ComplianceCategory.TOKEN_AUDIENCE,
    requirement: 'Token not expired',
    status: !isExpired ? 'pass' : 'fail',
    message: !isExpired
      ? `Token valid for ${timeRemaining} more seconds (expires: ${expiresAt.toISOString()})`
      : `Token expired ${Math.abs(timeRemaining)} seconds ago (expired: ${expiresAt.toISOString()})`,
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 9068 Section 2.2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9068#section-2.2',
    expected: `exp > current time (${now})`,
    actual: `exp = ${claims.exp} (${isExpired ? 'EXPIRED' : 'valid'})`,
    details: {
      currentTime: now,
      currentTimeISO: new Date(now * 1000).toISOString(),
      expirationTime: claims.exp,
      expirationTimeISO: expiresAt.toISOString(),
      issuedTime: claims.iat,
      issuedTimeISO: issuedAt?.toISOString(),
      timeRemaining: `${timeRemaining} seconds`,
      isExpired,
      tokenLifetime: claims.iat ? `${claims.exp - claims.iat} seconds` : 'unknown'
    }
  });

  // Test 6: Issuer validation
  if (authServerUrl && claims.iss !== authServerUrl) {
    results.push({
      id: 'audience-6',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Token issuer matches authorization server',
      status: 'warning',
      message: `Issuer mismatch: expected ${authServerUrl}, got ${claims.iss}`,
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 9068 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9068#section-2.2',
      expected: `iss: "${authServerUrl}"`,
      actual: `iss: "${claims.iss}"`,
      details: {
        expectedIssuer: authServerUrl,
        actualIssuer: claims.iss,
        matches: false,
        note: 'The issuer claim should match the authorization server URL that issued the token'
      }
    });
  } else if (authServerUrl) {
    results.push({
      id: 'audience-6',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Token issuer matches authorization server',
      status: 'pass',
      message: `Issuer correctly set: ${claims.iss}`,
      timestamp: new Date(),
      indentLevel: 1,
      expected: `iss: "${authServerUrl}"`,
      actual: `iss: "${claims.iss}"`,
      details: {
        expectedIssuer: authServerUrl,
        actualIssuer: claims.iss,
        matches: true
      }
    });
  }

  // Test 7: Additional claims validation
  validateAdditionalClaims(claims, results);

  return results;
}

/**
 * Validate additional token claims
 * @private
 */
function validateAdditionalClaims(
  claims: JWTAccessTokenClaims,
  results: ComplianceTestResult[]
): void {
  // Check for client_id
  if (claims.client_id) {
    results.push({
      id: 'audience-7',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Token contains client_id',
      status: 'pass',
      message: `Client ID: ${claims.client_id}`,
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 9068 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9068#section-2.2',
      details: {
        clientId: claims.client_id,
        note: 'The client_id claim identifies the OAuth client that requested the token'
      }
    });
  }

  // Check for scope
  if (claims.scope) {
    const scopes = claims.scope.split(' ');
    results.push({
      id: 'audience-8',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Token contains scope',
      status: 'pass',
      message: `Token scopes: ${claims.scope}`,
      timestamp: new Date(),
      indentLevel: 1,
      details: {
        scope: claims.scope,
        scopes: scopes,
        scopeCount: scopes.length,
        note: 'The scope claim indicates the permissions granted by this token'
      }
    });
  }

  // Check for sub (subject)
  if (claims.sub) {
    results.push({
      id: 'audience-9',
      category: ComplianceCategory.TOKEN_AUDIENCE,
      requirement: 'Token contains subject (sub)',
      status: 'pass',
      message: `Subject: ${claims.sub}`,
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 9068 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9068#section-2.2',
      details: {
        subject: claims.sub,
        note: 'The sub claim identifies the principal (user or service) that the token represents'
      }
    });
  }
}

/**
 * Check if token is expired
 * @private
 */
function isTokenExpired(claims: JWTAccessTokenClaims, clockSkewSeconds: number = 60): boolean {
  const now = Math.floor(Date.now() / 1000);
  return claims.exp < (now - clockSkewSeconds);
}
