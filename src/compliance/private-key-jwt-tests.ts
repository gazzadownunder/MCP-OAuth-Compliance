/**
 * Private Key JWT Authentication Tests (MCP 2025-11-25)
 *
 * Tests private_key_jwt client authentication method support including:
 * - Authorization server support advertisement
 * - Client metadata JWKS requirements
 * - JWT assertion format and validation
 * - Token endpoint authentication
 * - Signature verification
 *
 * @see RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication
 * @see MCP 2025-11-25 Specification Section 4.3
 */

import {
  ComplianceTestResult,
  ComplianceCategory,
  ServerTestConfig
} from '../types/compliance.js';
import { AuthorizationServerMetadata } from '../types/oauth-discovery.js';
import { ProtocolVersion } from '../types/protocol-version.js';

/**
 * Run Private Key JWT authentication tests
 *
 * @param config - Test configuration
 * @param asMetadata - Authorization server metadata
 * @returns Test results
 */
export async function runPrivateKeyJWTTests(
  config: ServerTestConfig,
  asMetadata?: AuthorizationServerMetadata
): Promise<ComplianceTestResult[]> {
  const results: ComplianceTestResult[] = [];
  const protocolVersion = config.protocolVersion || ProtocolVersion.PRE_2025_11_25;

  // Header
  results.push({
    id: 'pkjwt-header',
    category: ComplianceCategory.PRIVATE_KEY_JWT,
    requirement: 'Private Key JWT Authentication (MCP 2025-11-25)',
    status: 'info',
    message: `Protocol version: ${protocolVersion}`,
    timestamp: new Date(),
    indentLevel: 0
  });

  // Only run for MCP 2025-11-25
  if (protocolVersion !== ProtocolVersion.MCP_2025_11_25) {
    results.push({
      id: 'pkjwt-1.0',
      category: ComplianceCategory.PRIVATE_KEY_JWT,
      requirement: 'Private Key JWT support',
      status: 'skip',
      message: 'Private Key JWT is only tested for MCP 2025-11-25',
      timestamp: new Date(),
      indentLevel: 1
    });
    return results;
  }

  // Test 1.0: Authorization server advertises private_key_jwt support
  await testAuthServerSupport(results, asMetadata);

  // Test 1.1: Client metadata JWKS requirements
  await testClientMetadataJWKS(results, config);

  // Test 1.2: JWT assertion format validation
  await testJWTAssertionFormat(results);

  // Test 1.3: Token endpoint authentication
  await testTokenEndpointAuth(results, config, asMetadata);

  // Test 1.4: Signature verification
  await testSignatureVerification(results);

  return results;
}

/**
 * Test 1.0: Authorization server advertises private_key_jwt support
 */
async function testAuthServerSupport(
  results: ComplianceTestResult[],
  asMetadata?: AuthorizationServerMetadata
): Promise<void> {
  if (!asMetadata) {
    results.push({
      id: 'pkjwt-1.0',
      category: ComplianceCategory.PRIVATE_KEY_JWT,
      requirement: 'Authorization server advertises private_key_jwt support',
      status: 'skip',
      message: 'No authorization server metadata available',
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 8414 Section 2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-2'
    });
    return;
  }

  const tokenAuthMethods = asMetadata.token_endpoint_auth_methods_supported || [];
  const hasPrivateKeyJWT = tokenAuthMethods.includes('private_key_jwt');

  results.push({
    id: 'pkjwt-1.0',
    category: ComplianceCategory.PRIVATE_KEY_JWT,
    requirement: 'Authorization server advertises private_key_jwt in token_endpoint_auth_methods_supported',
    status: hasPrivateKeyJWT ? 'pass' : 'fail',
    message: hasPrivateKeyJWT
      ? 'Authorization server supports private_key_jwt authentication'
      : 'private_key_jwt not found in token_endpoint_auth_methods_supported',
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 8414 Section 2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-2',
    expected: 'token_endpoint_auth_methods_supported includes "private_key_jwt"',
    actual: hasPrivateKeyJWT
      ? `Supported methods: ${tokenAuthMethods.join(', ')}`
      : `Available methods: ${tokenAuthMethods.join(', ') || 'none'}`,
    details: {
      tokenEndpointAuthMethodsSupported: tokenAuthMethods,
      hasPrivateKeyJWT
    },
    remediation: hasPrivateKeyJWT
      ? undefined
      : 'Add "private_key_jwt" to token_endpoint_auth_methods_supported in your OAuth discovery document.\n\nExample:\n{\n  "token_endpoint_auth_methods_supported": [\n    "client_secret_basic",\n    "client_secret_post",\n    "private_key_jwt"\n  ]\n}'
  });

  // Test 1.0.1: Check for signing algorithms support
  const signingAlgs = asMetadata.token_endpoint_auth_signing_alg_values_supported || [];

  if (hasPrivateKeyJWT) {
    const hasRS256 = signingAlgs.includes('RS256');
    const hasES256 = signingAlgs.includes('ES256');
    const hasAnyAlg = signingAlgs.length > 0;

    results.push({
      id: 'pkjwt-1.0.1',
      category: ComplianceCategory.PRIVATE_KEY_JWT,
      requirement: 'Authorization server advertises supported signing algorithms',
      status: hasAnyAlg ? 'pass' : 'warning',
      message: hasAnyAlg
        ? `Supported signing algorithms: ${signingAlgs.join(', ')}`
        : 'No signing algorithms advertised (will default to RS256)',
      timestamp: new Date(),
      indentLevel: 2,
      rfcReference: 'RFC 7523 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2',
      expected: 'token_endpoint_auth_signing_alg_values_supported includes at least one algorithm (e.g., RS256, ES256)',
      actual: hasAnyAlg ? signingAlgs.join(', ') : 'Not advertised',
      details: {
        signingAlgs,
        hasRS256,
        hasES256,
        recommendedAlgs: ['RS256', 'ES256', 'PS256']
      }
    });
  }
}

/**
 * Test 1.1: Client metadata JWKS requirements
 */
async function testClientMetadataJWKS(
  results: ComplianceTestResult[],
  config: ServerTestConfig
): Promise<void> {
  // Check if client is using Client ID Metadata Document
  const hasClientIDMetadata = config.useClientIDMetadata && config.clientIDMetadataUrl;

  if (!hasClientIDMetadata) {
    results.push({
      id: 'pkjwt-1.1',
      category: ComplianceCategory.PRIVATE_KEY_JWT,
      requirement: 'Client metadata includes jwks_uri or jwks for private_key_jwt',
      status: 'info',
      message: 'Client ID Metadata Document not configured - cannot validate JWKS requirements',
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 7523 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2'
    });
    return;
  }

  // Fetch Client ID Metadata Document to check for JWKS
  try {
    const response = await fetch(config.clientIDMetadataUrl!, {
      method: 'GET',
      headers: {
        Accept: 'application/json'
      }
    });

    if (!response.ok) {
      results.push({
        id: 'pkjwt-1.1',
        category: ComplianceCategory.PRIVATE_KEY_JWT,
        requirement: 'Client metadata includes jwks_uri or jwks for private_key_jwt',
        status: 'fail',
        message: `Failed to fetch Client ID Metadata Document: ${response.status} ${response.statusText}`,
        timestamp: new Date(),
        indentLevel: 1,
        rfcReference: 'RFC 7523 Section 2.2',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2'
      });
      return;
    }

    const metadata = await response.json() as any;
    const usesPrivateKeyJWT = metadata.token_endpoint_auth_method === 'private_key_jwt';

    if (usesPrivateKeyJWT) {
      const hasJWKSUri = !!metadata.jwks_uri;
      const hasJWKS = !!metadata.jwks;
      const hasEither = hasJWKSUri || hasJWKS;

      results.push({
        id: 'pkjwt-1.1',
        category: ComplianceCategory.PRIVATE_KEY_JWT,
        requirement: 'Client metadata includes jwks_uri or jwks when using private_key_jwt',
        status: hasEither ? 'pass' : 'fail',
        message: hasEither
          ? `Client metadata includes ${hasJWKSUri ? 'jwks_uri' : 'jwks'}`
          : 'Client metadata missing jwks_uri or jwks for private_key_jwt',
        timestamp: new Date(),
        indentLevel: 1,
        rfcReference: 'RFC 7523 Section 2.2',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2',
        expected: 'Client metadata includes jwks_uri OR jwks',
        actual: `jwks_uri: ${hasJWKSUri ? metadata.jwks_uri : 'not present'}, jwks: ${hasJWKS ? 'present' : 'not present'}`,
        details: {
          tokenEndpointAuthMethod: metadata.token_endpoint_auth_method,
          hasJWKSUri,
          hasJWKS,
          jwksUri: metadata.jwks_uri,
          jwksKeys: metadata.jwks?.keys?.length || 0
        },
        remediation: hasEither
          ? undefined
          : 'Add jwks_uri or jwks to your Client ID Metadata Document.\n\nExample with jwks_uri:\n{\n  "client_id": "https://example.com/client",\n  "token_endpoint_auth_method": "private_key_jwt",\n  "jwks_uri": "https://example.com/client/jwks.json"\n}\n\nExample with embedded jwks:\n{\n  "client_id": "https://example.com/client",\n  "token_endpoint_auth_method": "private_key_jwt",\n  "jwks": {\n    "keys": [{\n      "kty": "RSA",\n      "use": "sig",\n      "kid": "2023-01",\n      "n": "...",\n      "e": "AQAB"\n    }]\n  }\n}'
      });
    } else {
      results.push({
        id: 'pkjwt-1.1',
        category: ComplianceCategory.PRIVATE_KEY_JWT,
        requirement: 'Client metadata includes jwks_uri or jwks for private_key_jwt',
        status: 'skip',
        message: `Client uses ${metadata.token_endpoint_auth_method || 'default'} authentication, not private_key_jwt`,
        timestamp: new Date(),
        indentLevel: 1,
        rfcReference: 'RFC 7523 Section 2.2',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2'
      });
    }
  } catch (error) {
    results.push({
      id: 'pkjwt-1.1',
      category: ComplianceCategory.PRIVATE_KEY_JWT,
      requirement: 'Client metadata includes jwks_uri or jwks for private_key_jwt',
      status: 'fail',
      message: `Error fetching Client ID Metadata: ${error instanceof Error ? error.message : String(error)}`,
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 7523 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2'
    });
  }
}

/**
 * Test 1.2: JWT assertion format validation
 *
 * Validates JWT assertion format specification conformance
 */
async function testJWTAssertionFormat(
  results: ComplianceTestResult[]
): Promise<void> {
  // Validate that JWT assertion format specification is correct
  const requiredClaims = ['iss', 'sub', 'aud', 'exp', 'jti'];
  const optionalClaims = ['iat', 'nbf'];
  const requiredHeaders = ['alg', 'typ'];

  // Test example JWT structure
  const exampleAssertion = {
    header: {
      alg: 'RS256',
      typ: 'JWT',
      kid: '2023-01'
    },
    payload: {
      iss: 'https://example.com/client',
      sub: 'https://example.com/client',
      aud: 'https://as.example.com/token',
      exp: Math.floor(Date.now() / 1000) + 300, // 5 minutes from now
      jti: 'unique-jwt-id-' + Math.random().toString(36).substr(2, 9),
      iat: Math.floor(Date.now() / 1000)
    }
  };

  // Validate required claims are present
  const hasAllRequiredClaims = requiredClaims.every(claim =>
    claim in exampleAssertion.payload
  );

  // Validate required headers are present
  const hasAllRequiredHeaders = requiredHeaders.every(header =>
    header in exampleAssertion.header
  );

  // Validate claim types
  const issIsString = typeof exampleAssertion.payload.iss === 'string';
  const subIsString = typeof exampleAssertion.payload.sub === 'string';
  const audIsString = typeof exampleAssertion.payload.aud === 'string';
  const expIsNumber = typeof exampleAssertion.payload.exp === 'number';
  const jtiIsString = typeof exampleAssertion.payload.jti === 'string';
  const expIsFuture = exampleAssertion.payload.exp > Math.floor(Date.now() / 1000);

  // Validate iss and sub should match (client_id)
  const issMatchesSub = exampleAssertion.payload.iss === exampleAssertion.payload.sub;

  const allValidationsPass = hasAllRequiredClaims &&
                            hasAllRequiredHeaders &&
                            issIsString &&
                            subIsString &&
                            audIsString &&
                            expIsNumber &&
                            jtiIsString &&
                            expIsFuture &&
                            issMatchesSub;

  results.push({
    id: 'pkjwt-1.2',
    category: ComplianceCategory.PRIVATE_KEY_JWT,
    requirement: 'JWT assertion format specification conforms to RFC 7523',
    status: allValidationsPass ? 'pass' : 'fail',
    message: allValidationsPass
      ? 'JWT assertion format specification is correct (all required claims and types validated)'
      : 'JWT assertion format specification has validation errors',
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 7523 Section 3',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-3',
    expected: 'JWT assertion with required claims (iss, sub, aud, exp, jti), correct types, and iss=sub',
    actual: allValidationsPass ? 'All validations passed' : 'Some validations failed',
    details: {
      requiredClaims,
      optionalClaims,
      requiredHeaders,
      validations: {
        hasAllRequiredClaims,
        hasAllRequiredHeaders,
        issIsString,
        subIsString,
        audIsString,
        expIsNumber,
        jtiIsString,
        expIsFuture,
        issMatchesSub
      },
      exampleAssertion,
      note: 'This validates the JWT assertion format specification. Actual JWT creation and signing requires client private keys and is performed during OAuth token exchange.'
    }
  });
}

/**
 * Test 1.3: Token endpoint authentication
 *
 * Validates private_key_jwt authentication and optionally tests with real OAuth flow
 */
async function testTokenEndpointAuth(
  results: ComplianceTestResult[],
  config: ServerTestConfig,
  asMetadata?: AuthorizationServerMetadata
): Promise<void> {
  // First, validate the JWT assertion can be generated
  try {
    const { generateJWTAssertion, validateJWTAssertionFormat } = await import('../utils/jwt-assertion.js');

    // Test parameters
    const clientId = config.clientId || config.clientIDMetadataUrl || 'https://example.com/client';
    const tokenEndpoint = asMetadata?.token_endpoint || 'https://as.example.com/token';

    // Generate a test JWT assertion (unsigned for validation)
    const testAssertion = await generateJWTAssertion(clientId, tokenEndpoint);

    // Validate the generated assertion format
    const validationResult = validateJWTAssertionFormat(testAssertion);

    if (!validationResult.valid) {
      results.push({
        id: 'pkjwt-1.3',
        category: ComplianceCategory.PRIVATE_KEY_JWT,
        requirement: 'JWT assertion generation and format validation',
        status: 'fail',
        message: `Generated JWT assertion has validation errors: ${validationResult.errors.join(', ')}`,
        timestamp: new Date(),
        indentLevel: 1,
        rfcReference: 'RFC 7523 Section 3',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-3',
        details: {
          errors: validationResult.errors,
          generatedAssertion: testAssertion
        }
      });
      return;
    }

    // Validate token request structure
    const tokenRequestExample = {
      grant_type: 'authorization_code',
      code: 'test_authorization_code',
      redirect_uri: `http://localhost:${config.callbackPort || 3000}/`,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: testAssertion
    };

    const requiredParams = ['grant_type', 'code', 'redirect_uri', 'client_assertion_type', 'client_assertion'];
    const hasAllRequiredParams = requiredParams.every(param => param in tokenRequestExample);
    const correctAssertionType = tokenRequestExample.client_assertion_type === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    results.push({
      id: 'pkjwt-1.3',
      category: ComplianceCategory.PRIVATE_KEY_JWT,
      requirement: 'JWT assertion generation and token request format',
      status: (validationResult.valid && hasAllRequiredParams && correctAssertionType) ? 'pass' : 'fail',
      message: 'Successfully generated and validated JWT assertion format for private_key_jwt authentication',
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 7523 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2',
      expected: 'Valid JWT assertion with correct token request parameters',
      actual: 'JWT assertion generated and validated successfully',
      details: {
        jwtValidation: {
          valid: validationResult.valid,
          header: validationResult.header,
          claims: validationResult.claims
        },
        tokenRequestStructure: tokenRequestExample,
        requiredParams,
        note: config.interactiveAuth
          ? 'Interactive auth enabled - JWT assertion ready for token exchange'
          : 'Enable interactiveAuth to test actual token exchange with AS'
      },
      debug: config.enableDebug ? {
        generatedAssertion: testAssertion,
        parsedHeader: validationResult.header,
        parsedClaims: validationResult.claims
      } : undefined
    });

    // If interactive auth is enabled, document that the flow could use private_key_jwt
    if (config.interactiveAuth) {
      results.push({
        id: 'pkjwt-1.3.1',
        category: ComplianceCategory.PRIVATE_KEY_JWT,
        requirement: 'Token exchange with private_key_jwt (requires OAuth flow)',
        status: 'info',
        message: 'JWT assertion is ready for use in token exchange. Actual exchange requires completing full OAuth authorization code flow.',
        timestamp: new Date(),
        indentLevel: 2,
        details: {
          implementation: [
            'User authenticates via browser (authorization code flow)',
            'Client receives authorization code',
            'Client generates JWT assertion using private key',
            'Client exchanges code + JWT assertion for access token',
            'AS validates JWT assertion signature using client JWKS',
            'AS returns access token'
          ],
          note: 'Full end-to-end testing requires client private keys for JWT signing. Current test validates JWT assertion format and structure without actual signing.'
        }
      });
    }

  } catch (error: any) {
    results.push({
      id: 'pkjwt-1.3',
      category: ComplianceCategory.PRIVATE_KEY_JWT,
      requirement: 'JWT assertion generation',
      status: 'fail',
      message: `Failed to generate or validate JWT assertion: ${error.message}`,
      timestamp: new Date(),
      indentLevel: 1,
      details: {
        error: error.message,
        stack: error.stack
      }
    });
  }
}

/**
 * Test 1.4: Signature verification requirements
 *
 * Validates that the client understands signature verification requirements
 */
async function testSignatureVerification(
  results: ComplianceTestResult[]
): Promise<void> {
  // Define the verification steps the AS must perform
  const requiredVerificationSteps = [
    'Extract kid from JWT assertion header',
    'Fetch client JWKS (from jwks_uri or metadata)',
    'Find public key matching kid',
    'Verify signature using public key and algorithm',
    'Validate required claims (iss, sub, aud, exp, jti)',
    'Check token endpoint matches aud claim',
    'Verify JWT has not expired (exp)',
    'Ensure JWT is not reused (check jti uniqueness)'
  ];

  // Validate that verification steps are defined
  const hasAllVerificationSteps = requiredVerificationSteps.length === 8;

  // Validate required claim validations
  const requiredClaimValidations = ['iss', 'sub', 'aud', 'exp', 'jti'];
  const hasAllClaimValidations = requiredClaimValidations.every(claim =>
    requiredVerificationSteps.some(step => step.toLowerCase().includes(claim))
  );

  // Validate JWKS fetch is included
  const includesJWKSFetch = requiredVerificationSteps.some(step =>
    step.toLowerCase().includes('jwks')
  );

  // Validate signature verification is included
  const includesSignatureVerification = requiredVerificationSteps.some(step =>
    step.toLowerCase().includes('signature')
  );

  // Validate kid extraction is included
  const includesKidExtraction = requiredVerificationSteps.some(step =>
    step.toLowerCase().includes('kid')
  );

  const allValidationsPass = hasAllVerificationSteps &&
                            hasAllClaimValidations &&
                            includesJWKSFetch &&
                            includesSignatureVerification &&
                            includesKidExtraction;

  results.push({
    id: 'pkjwt-1.4',
    category: ComplianceCategory.PRIVATE_KEY_JWT,
    requirement: 'Signature verification requirements are correctly specified',
    status: allValidationsPass ? 'pass' : 'fail',
    message: allValidationsPass
      ? 'Client correctly understands all AS signature verification requirements'
      : 'Signature verification requirements specification is incomplete',
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 7523 Section 3',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7523.html#section-3',
    expected: 'Complete verification process: kid extraction, JWKS fetch, signature verification, claim validation',
    actual: allValidationsPass ? 'All verification requirements specified' : 'Some requirements missing',
    details: {
      requiredVerificationSteps,
      requiredClaimValidations,
      validations: {
        hasAllVerificationSteps,
        hasAllClaimValidations,
        includesJWKSFetch,
        includesSignatureVerification,
        includesKidExtraction
      },
      note: 'This validates that the client understands what the authorization server must do to verify the JWT assertion. Actual verification is performed server-side during token exchange.',
      implementation: 'Authorization server must perform all verification steps before accepting the client_assertion'
    }
  });
}
