/**
 * Resource Parameter Tests (RFC 8707 - MCP 2025-11-25)
 *
 * Tests resource parameter support as required by MCP 2025-11-25.
 * The resource parameter allows clients to indicate the target resource server.
 */

import {
  ComplianceTestResult,
  ComplianceCategory,
  ServerTestConfig
} from '../types/compliance.js';
import { ProtocolVersion } from '../types/protocol-version.js';
import { buildAuthorizationUrl, AuthorizationRequestParams } from '../utils/oauth-flow.js';

/**
 * Run resource parameter tests
 *
 * @param config - Test configuration
 * @param resourceUrl - The MCP server URL (resource server)
 * @returns Test results
 */
export async function runResourceParameterTests(
  config: ServerTestConfig,
  resourceUrl: string
): Promise<ComplianceTestResult[]> {
  const results: ComplianceTestResult[] = [];
  const protocolVersion = config.protocolVersion || ProtocolVersion.PRE_2025_11_25;

  // Header
  results.push({
    id: 'resource-header',
    category: ComplianceCategory.RESOURCE_PARAMETER,
    requirement: 'Resource Parameter (RFC 8707)',
    status: 'info',
    message: `Protocol version: ${protocolVersion}`,
    timestamp: new Date(),
    indentLevel: 0
  });

  // For MCP 2025-11-25, resource parameter is REQUIRED
  if (protocolVersion !== ProtocolVersion.MCP_2025_11_25) {
    results.push({
      id: 'resource-1',
      category: ComplianceCategory.RESOURCE_PARAMETER,
      requirement: 'Resource parameter support',
      status: 'skip',
      message: 'Resource parameter is optional for pre-2025-11-25',
      timestamp: new Date(),
      indentLevel: 1
    });
    return results;
  }

  // Test 1: Resource parameter configuration
  const resourceParam = config.resourceParameter || config.serverUrl || resourceUrl;

  results.push({
    id: 'resource-1',
    category: ComplianceCategory.RESOURCE_PARAMETER,
    requirement: 'Resource parameter configured',
    status: resourceParam ? 'pass' : 'fail',
    message: resourceParam
      ? `Resource: ${resourceParam}`
      : 'Resource parameter not configured',
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 8707 Section 2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707#section-2'
  });

  if (!resourceParam) {
    return results;
  }

  // Test 2: Resource parameter URL format validation
  let isValidUrl = false;
  try {
    new URL(resourceParam);
    isValidUrl = true;
  } catch {
    isValidUrl = false;
  }

  results.push({
    id: 'resource-2',
    category: ComplianceCategory.RESOURCE_PARAMETER,
    requirement: 'Resource parameter is valid URL',
    status: isValidUrl ? 'pass' : 'fail',
    message: isValidUrl
      ? 'Resource parameter is a valid URL'
      : `Invalid URL: ${resourceParam}`,
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 8707 Section 2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707#section-2',
    expected: 'Absolute URI identifying the resource server',
    actual: resourceParam,
    remediation: 'Use the full URL of the MCP server as the resource parameter'
  });

  // Test 3: Resource parameter in authorization request
  const authParams: AuthorizationRequestParams = {
    authorizationEndpoint: 'https://example.com/authorize',
    clientId: 'test-client',
    redirectUri: 'http://localhost:3000/callback',
    scope: 'read write',
    state: 'test-state',
    codeChallenge: 'test-challenge',
    codeChallengeMethod: 'S256',
    resource: resourceParam
  };

  const authUrl = buildAuthorizationUrl(authParams);
  const url = new URL(authUrl);
  const resourceInUrl = url.searchParams.get('resource');

  results.push({
    id: 'resource-3',
    category: ComplianceCategory.RESOURCE_PARAMETER,
    requirement: 'Resource parameter in authorization request',
    status: resourceInUrl === resourceParam ? 'pass' : 'fail',
    message: resourceInUrl === resourceParam
      ? `Resource parameter correctly included: ${resourceParam}`
      : `Mismatch: expected ${resourceParam}, got ${resourceInUrl}`,
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 8707 Section 2.1',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707#section-2.1'
  });

  // Test 4: Multiple resource parameters (if supported)
  if (Array.isArray(config.resourceParameter)) {
    results.push({
      id: 'resource-4',
      category: ComplianceCategory.RESOURCE_PARAMETER,
      requirement: 'Multiple resource parameters',
      status: 'info',
      message: `Multiple resources configured: ${config.resourceParameter.length}`,
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 8707 Section 2.1',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707#section-2.1'
    });
  }

  // Test 5: Resource parameter best practices
  const httpsResource = resourceParam.startsWith('https://');

  results.push({
    id: 'resource-5',
    category: ComplianceCategory.RESOURCE_PARAMETER,
    requirement: 'Resource uses HTTPS',
    status: httpsResource ? 'pass' : 'warning',
    message: httpsResource
      ? 'Resource URL uses HTTPS'
      : 'Resource URL should use HTTPS in production',
    timestamp: new Date(),
    indentLevel: 1
  });

  return results;
}

/**
 * Validate token response contains resource indicator
 *
 * @param tokenResponse - Token response from authorization server
 * @param expectedResource - Expected resource URL
 * @returns Test result
 */
export function validateTokenResourceParameter(
  tokenResponse: any,
  expectedResource: string
): ComplianceTestResult {
  const resourceInToken = tokenResponse.resource;

  if (!resourceInToken) {
    return {
      id: 'resource-token-1',
      category: ComplianceCategory.RESOURCE_PARAMETER,
      requirement: 'Resource in token response',
      status: 'warning',
      message: 'Token response does not include resource parameter (optional but recommended)',
      timestamp: new Date(),
      rfcReference: 'RFC 8707 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707#section-2.2'
    };
  }

  // Check if resource matches
  const resources = Array.isArray(resourceInToken) ? resourceInToken : [resourceInToken];
  const matches = resources.includes(expectedResource);

  return {
    id: 'resource-token-1',
    category: ComplianceCategory.RESOURCE_PARAMETER,
    requirement: 'Resource in token response matches request',
    status: matches ? 'pass' : 'fail',
    message: matches
      ? `Resource in token response matches: ${expectedResource}`
      : `Mismatch: expected ${expectedResource}, got ${resources.join(', ')}`,
    timestamp: new Date(),
    rfcReference: 'RFC 8707 Section 2.2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707#section-2.2',
    expected: expectedResource,
    actual: resources.join(', ')
  };
}
