/**
 * Unified Client Registration Tests
 *
 * Tests client registration for both pre-2025-11-25 and MCP 2025-11-25 protocols.
 * Implements the priority order:
 * 1. Preregistration (pre-configured credentials)
 * 2. Client ID Metadata Document (MCP 2025-11-25 only)
 * 3. Dynamic Client Registration via RFC 7591 (fallback)
 */

import {
  ComplianceTestResult,
  ComplianceCategory,
  ClientRegistrationMethod,
  ServerTestConfig
} from '../types/compliance.js';
import { ProtocolVersion } from '../types/protocol-version.js';
import { DCRClient } from '../client/dcr-client.js';
import { TEST_METADATA } from './test-metadata.js';
import { isValidClientIDUrl, shouldUseHTTPS } from '../types/client-id-metadata.js';

/**
 * Client registration context
 * Stores the result of successful registration
 */
export interface ClientRegistrationContext {
  method: ClientRegistrationMethod;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  registrationAccessToken?: string;
  registrationClientUri?: string;
}

/**
 * Run unified client registration tests
 *
 * Tests all three registration methods and displays results for each:
 * 1. Preregistration (priority 1)
 * 2. Client ID Metadata Document (priority 2, MCP 2025-11-25 only)
 * 3. Dynamic Client Registration (priority 3, fallback)
 *
 * The first successful method provides the context for OAuth flow.
 *
 * @param config - Test configuration
 * @param dcrClient - DCR client instance
 * @param asMetadata - Authorization Server metadata (from cache, optional)
 * @returns Test results and registration context
 */
export async function runClientRegistrationTests(
  config: ServerTestConfig,
  dcrClient: DCRClient | null,
  asMetadata?: Record<string, any>
): Promise<{
  results: ComplianceTestResult[];
  context?: ClientRegistrationContext;
}> {
  const results: ComplianceTestResult[] = [];
  const protocolVersion = config.protocolVersion || ProtocolVersion.PRE_2025_11_25;
  let context: ClientRegistrationContext | undefined;

  if (protocolVersion === ProtocolVersion.PRE_2025_11_25) {
    // Pre-2025-11-25: Test Preregistration and DCR (same priority order as 2025-11-25)
    results.push({
      id: 'client-reg-header',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Client Registration',
      status: 'info',
      message: 'Protocol: Pre-2025-11-25. Testing registration methods in priority order.',
      timestamp: new Date(),
      indentLevel: 0
    });

    // Test Priority 1: Preregistration
    const preregResult = runPreregistrationTests(config, results);
    if (preregResult.context && !context) {
      context = preregResult.context;
    }

    // Test Priority 2: Dynamic Client Registration (RFC 7591)
    const dcrResult = await runDynamicClientRegistrationTests(config, dcrClient, results);
    if (dcrResult.context && !context) {
      context = dcrResult.context;
    }
  } else {
    // MCP 2025-11-25: Test all three methods in priority order
    results.push({
      id: 'client-reg-header',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Client Registration',
      status: 'info',
      message: 'Protocol: MCP 2025-11-25. Testing all registration methods in priority order.',
      timestamp: new Date(),
      indentLevel: 0
    });

    // Test Priority 1: Preregistration
    const preregResult = runPreregistrationTests(config, results);
    if (preregResult.context && !context) {
      context = preregResult.context;
    }

    // Test Priority 2: Client ID Metadata Document
    const clientIdMetadataResult = await runClientIDMetadataTests(config, dcrClient, asMetadata, results);
    if (clientIdMetadataResult.context && !context) {
      context = clientIdMetadataResult.context;
    }

    // Test Priority 3: Dynamic Client Registration (RFC 7591)
    const dcrResult = await runDynamicClientRegistrationTests(config, dcrClient, results);
    if (dcrResult.context && !context) {
      context = dcrResult.context;
    }
  }

  return { results, context };
}

/**
 * Test Priority 1: Preregistration
 */
function runPreregistrationTests(
  config: ServerTestConfig,
  results: ComplianceTestResult[]
): {
  results: ComplianceTestResult[];
  context?: ClientRegistrationContext;
} {
  const isConfigured = config.preregisteredClient || config.usePreConfiguredClient;
  const clientId = config.preregisteredClient?.clientId || config.clientId || '';
  const clientSecret = config.preregisteredClient?.clientSecret || config.clientSecret;
  const redirectUri = config.preregisteredClient?.redirectUri || config.redirectUri || '';

  // Main preregistration test
  results.push({
    id: 'client-reg-1',
    category: ComplianceCategory.CLIENT_REGISTRATION,
    requirement: 'Preregistration (Priority #1)',
    status: isConfigured ? (clientId ? 'pass' : 'fail') : 'skip',
    message: isConfigured
      ? clientId
        ? 'Using preregistered client credentials'
        : 'Preregistration enabled but client ID not provided'
      : 'Preregistration not configured',
    timestamp: new Date(),
    registrationMethod: ClientRegistrationMethod.PREREGISTERED,
    indentLevel: 1
  });

  // Only show detailed tests if configured
  if (isConfigured) {
    results.push({
      id: 'client-reg-1.1',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Client ID validation',
      status: clientId ? 'pass' : 'fail',
      message: clientId ? `Client ID: ${clientId}` : 'Client ID not provided',
      timestamp: new Date(),
      indentLevel: 2
    });

    results.push({
      id: 'client-reg-1.2',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Redirect URI validation',
      status: redirectUri ? 'pass' : 'warning',
      message: redirectUri ? `Redirect URI: ${redirectUri}` : 'Redirect URI not provided',
      timestamp: new Date(),
      indentLevel: 2
    });

    if (clientId) {
      const context: ClientRegistrationContext = {
        method: ClientRegistrationMethod.PREREGISTERED,
        clientId,
        clientSecret,
        redirectUri
      };
      return { results, context };
    }
  }

  return { results };
}

/**
 * Test Priority 2: Client ID Metadata Document (MCP 2025-11-25)
 */
async function runClientIDMetadataTests(
  config: ServerTestConfig,
  dcrClient: DCRClient | null,
  asMetadata: Record<string, any> | undefined,
  results: ComplianceTestResult[]
): Promise<{
  results: ComplianceTestResult[];
  context?: ClientRegistrationContext;
}> {
  const isConfigured = config.useClientIDMetadata || config.clientIDMetadataUrl;
  const metadataUrl = config.clientIDMetadataUrl;

  // Main Client ID Metadata test
  results.push({
    id: 'client-reg-2',
    category: ComplianceCategory.CLIENT_REGISTRATION,
    requirement: 'Client ID Metadata Document (Priority #2)',
    status: isConfigured ? 'info' : 'skip',
    message: isConfigured
      ? 'Attempting Client ID Metadata Document registration'
      : 'Client ID Metadata Document not configured',
    timestamp: new Date(),
    registrationMethod: ClientRegistrationMethod.CLIENT_ID_METADATA_DOCUMENT,
    indentLevel: 1
  });

  // Always check AS metadata for client_id_metadata_document_supported (independent of configuration)
  // Try parameter first, then dcrClient as fallback
  const metadata = asMetadata || (dcrClient ? dcrClient.getAuthServerMetadata() : null);

  if (metadata) {
    const supported = metadata.client_id_metadata_document_supported === true;
    results.push({
      id: 'client-reg-2.1',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'AS advertises client_id_metadata_document_supported',
      status: supported ? 'pass' : 'info',
      message: supported
        ? 'Authorization Server supports Client ID Metadata Documents'
        : 'Authorization Server does not advertise support for Client ID Metadata Documents',
      timestamp: new Date(),
      indentLevel: 2,
      details: {
        client_id_metadata_document_supported: metadata.client_id_metadata_document_supported
      }
    });
  } else {
    results.push({
      id: 'client-reg-2.1',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'AS advertises client_id_metadata_document_supported',
      status: 'info',
      message: 'Authorization Server metadata not available yet - run AS Discovery tests first',
      timestamp: new Date(),
      indentLevel: 2
    });
  }

  // If not configured or no client, skip detailed tests
  if (!isConfigured || !metadataUrl || !dcrClient) {
    return { results };
  }

  const handler = dcrClient.getClientIDMetadataHandler();
  if (!handler) {
    results.push({
      id: 'client-reg-2.2',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Client ID Metadata handler',
      status: 'fail',
      message: 'Client ID Metadata handler not available (not MCP 2025-11-25?)',
      timestamp: new Date(),
      indentLevel: 2
    });
    return { results };
  }

  try {
    // Test 2.2: URL Format Validation
    const urlValid = isValidClientIDUrl(metadataUrl);
    const httpsCheck = shouldUseHTTPS(metadataUrl);

    let urlStatus: 'pass' | 'fail' | 'warning' = urlValid ? 'pass' : 'fail';
    let urlMessage = '';

    if (!urlValid) {
      try {
        const url = new URL(metadataUrl);
        if (!url.pathname || url.pathname === '/') {
          urlMessage = 'URL must include a path component (e.g., /client or /metadata)';
        } else {
          urlMessage = 'URL must use HTTP or HTTPS protocol';
        }
      } catch {
        urlMessage = 'Invalid URL format';
      }
    } else if (!httpsCheck.valid) {
      urlStatus = 'warning';
      urlMessage = httpsCheck.reason || 'Should use HTTPS in production';
    } else {
      urlMessage = 'Valid URL format with path component';
    }

    results.push({
      id: 'client-reg-2.2',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'URL format validation',
      status: urlStatus,
      message: urlMessage,
      expected: 'URL with protocol and path (e.g., https://example.com/client)',
      actual: metadataUrl,
      timestamp: new Date(),
      indentLevel: 2
    });

    // Validate metadata document
    const validationResult = await handler.validateMetadata(metadataUrl, config.enableDebug || false);

    // Test 2.3: Overall validation status
    results.push({
      id: 'client-reg-2.3',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Metadata document fetchable and parsable',
      status: validationResult.metadata ? 'pass' : 'fail',
      message: validationResult.metadata
        ? 'Successfully fetched and parsed metadata document'
        : `Failed to fetch/parse: ${validationResult.errors.join(', ')}`,
      expected: 'Valid JSON document with client metadata',
      actual: validationResult.metadata ? 'Document fetched successfully' : `Error: ${validationResult.errors[0] || 'Unknown error'}`,
      details: validationResult.metadata ? validationResult.metadata : undefined,
      debug: validationResult.debug,
      timestamp: new Date(),
      indentLevel: 2
    });

    const metadata = validationResult.metadata;

    // If we couldn't fetch the document, show individual field requirements as "fail"
    if (!metadata) {
      // Show what fields we expected but couldn't validate
      results.push({
        id: 'client-reg-2.4',
        category: ComplianceCategory.CLIENT_REGISTRATION,
        requirement: 'client_id field present',
        status: 'fail',
        message: 'Cannot validate - document not fetched',
        expected: `client_id matching URL: ${metadataUrl}`,
        actual: 'Document not fetched',
        timestamp: new Date(),
        indentLevel: 2
      });

      results.push({
        id: 'client-reg-2.5',
        category: ComplianceCategory.CLIENT_REGISTRATION,
        requirement: 'client_name field present',
        status: 'fail',
        message: 'Cannot validate - document not fetched',
        expected: 'Non-empty string (e.g., "My Application")',
        actual: 'Document not fetched',
        timestamp: new Date(),
        indentLevel: 2
      });

      results.push({
        id: 'client-reg-2.6',
        category: ComplianceCategory.CLIENT_REGISTRATION,
        requirement: 'redirect_uris field present',
        status: 'fail',
        message: 'Cannot validate - document not fetched',
        expected: 'Array of redirect URIs (e.g., ["https://example.com/callback"])',
        actual: 'Document not fetched',
        timestamp: new Date(),
        indentLevel: 2
      });

      return { results };
    }

    // Test 2.4: client_id field present and matches URL
    const clientIdMatches = metadata.client_id === metadataUrl;
    results.push({
      id: 'client-reg-2.4',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'client_id matches metadata URL',
      status: clientIdMatches ? 'pass' : 'fail',
      message: clientIdMatches
        ? `client_id correctly matches: ${metadataUrl}`
        : `Mismatch: expected ${metadataUrl}, got ${metadata.client_id || '(missing)'}`,
      expected: metadataUrl,
      actual: metadata.client_id || '(missing)',
      timestamp: new Date(),
      indentLevel: 2
    });

    // Test 2.5: client_name field present
    results.push({
      id: 'client-reg-2.5',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'client_name field present',
      status: metadata.client_name ? 'pass' : 'fail',
      message: metadata.client_name
        ? `Client name: ${metadata.client_name}`
        : 'Missing required field: client_name',
      expected: 'Non-empty string (e.g., "My Application")',
      actual: metadata.client_name || '(missing)',
      timestamp: new Date(),
      indentLevel: 2
    });

    // Test 2.6: redirect_uris field present
    const hasRedirectUris = metadata.redirect_uris && metadata.redirect_uris.length > 0;
    results.push({
      id: 'client-reg-2.6',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'redirect_uris field present',
      status: hasRedirectUris ? 'pass' : 'fail',
      message: hasRedirectUris
        ? `${metadata.redirect_uris.length} redirect URI(s) configured`
        : 'Missing required field: redirect_uris',
      expected: 'Array of redirect URIs (e.g., ["https://example.com/callback"])',
      actual: hasRedirectUris
        ? `[${metadata.redirect_uris.map(u => `"${u}"`).join(', ')}]`
        : '(missing)',
      timestamp: new Date(),
      indentLevel: 2
    });

    // Only proceed with registration if all required fields are present
    if (!clientIdMatches || !metadata.client_name || !hasRedirectUris) {
      return { results };
    }

    // Success - create context
    const context: ClientRegistrationContext = {
      method: ClientRegistrationMethod.CLIENT_ID_METADATA_DOCUMENT,
      clientId: metadataUrl,
      redirectUri: metadata.redirect_uris?.[0]
    };

    results.push({
      id: 'client-reg-2.7',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Client registration complete',
      status: 'pass',
      message: `Using Client ID Metadata Document: ${metadataUrl}`,
      timestamp: new Date(),
      indentLevel: 2
    });

    return { results, context };
  } catch (error) {
    results.push({
      id: 'client-reg-2.error',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Client ID Metadata Document registration',
      status: 'fail',
      message: `Error: ${error instanceof Error ? error.message : String(error)}`,
      timestamp: new Date(),
      indentLevel: 2
    });
    return { results };
  }
}

/**
 * Test Priority 3: Dynamic Client Registration (RFC 7591)
 */
async function runDynamicClientRegistrationTests(
  config: ServerTestConfig,
  dcrClient: DCRClient | null,
  results: ComplianceTestResult[]
): Promise<{
  results: ComplianceTestResult[];
  context?: ClientRegistrationContext;
}> {
  const isSkipped = config.skipDCR;

  console.log('[DCR Test] isSkipped:', isSkipped, 'dcrClient:', dcrClient ? 'present' : 'null');

  // Main DCR test
  results.push({
    id: 'client-reg-3',
    category: ComplianceCategory.CLIENT_REGISTRATION,
    requirement: 'Dynamic Client Registration - RFC 7591 (Priority #3)',
    status: isSkipped ? 'skip' : !dcrClient ? 'fail' : 'info',
    message: isSkipped
      ? 'Dynamic Client Registration skipped (skipDCR option enabled)'
      : !dcrClient
      ? 'DCR client not available - cannot perform Dynamic Client Registration'
      : 'Attempting Dynamic Client Registration (RFC 7591)',
    timestamp: new Date(),
    registrationMethod: ClientRegistrationMethod.DYNAMIC_CLIENT_REGISTRATION,
    indentLevel: 1
  });

  // If skipped or no client, don't run detailed tests
  if (isSkipped || !dcrClient) {
    console.log('[DCR Test] Skipping - isSkipped:', isSkipped, 'no client:', !dcrClient);
    return { results };
  }

  try {
    // Check if registration endpoint is available
    let registrationEndpoint: string;
    try {
      registrationEndpoint = dcrClient.getRegistrationEndpoint();
    } catch (error) {
      results.push({
        id: 'client-reg-3.1',
        category: ComplianceCategory.CLIENT_REGISTRATION,
        requirement: 'Registration endpoint discovery',
        status: 'fail',
        message: `No registration endpoint found: ${error instanceof Error ? error.message : String(error)}`,
        timestamp: new Date(),
        indentLevel: 2,
        ...TEST_METADATA['dcr-3.1']
      });
      return { results };
    }

    results.push({
      id: 'client-reg-3.1',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Registration endpoint discovery',
      status: 'pass',
      message: `Registration endpoint: ${registrationEndpoint}`,
      timestamp: new Date(),
      indentLevel: 2
    });

    // Prepare client metadata
    const redirectUri = config.redirectUri || `http://localhost:${config.callbackPort || 3000}/callback`;
    const clientMetadata: any = {
      client_name: 'MCP OAuth Compliance Tester',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: config.scope || 'read write',
      token_endpoint_auth_method: 'none' // Public client
    };

    // Register client
    const response = await dcrClient.registerClient(clientMetadata);

    results.push({
      id: 'client-reg-3.2',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Client registration (RFC 7591)',
      status: 'pass',
      message: `Client registered: ${response.client_id}`,
      timestamp: new Date(),
      indentLevel: 2,
      details: {
        client_id: response.client_id,
        client_secret: response.client_secret ? '***' : undefined,
        registration_client_uri: response.registration_client_uri
      }
    });

    // Validate registration_client_uri format (RFC 7592)
    if (response.registration_client_uri) {
      const isRelativeUrl = response.registration_client_uri.startsWith('/');
      const isFullyQualified = response.registration_client_uri.startsWith('http://') ||
                               response.registration_client_uri.startsWith('https://');

      if (isRelativeUrl || !isFullyQualified) {
        results.push({
          id: 'client-reg-3.2.1',
          category: ComplianceCategory.CLIENT_REGISTRATION,
          requirement: 'registration_client_uri must be fully qualified URL (RFC 7592)',
          status: 'warning',
          message: `Server returned relative URL: ${response.registration_client_uri}`,
          timestamp: new Date(),
          indentLevel: 3,
          expected: 'Fully qualified URL (e.g., https://server.com/register/client-id)',
          actual: response.registration_client_uri,
          rfcReference: 'RFC 7592 Section 2',
          rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7592.html#section-2',
          remediation: `The registration_client_uri field MUST contain a fully qualified URL per RFC 7592.\n\nExpected: "https://mcp.canva.com${response.registration_client_uri}"\nActual: "${response.registration_client_uri}"\n\nFix: Update your registration endpoint to return the complete URL including scheme and host.`
        });

        // Construct the proper URL for internal use
        const authServer = dcrClient.getAuthorizationServer();
        if (authServer && isRelativeUrl) {
          const properUrl = `${authServer}${response.registration_client_uri}`;
          response.registration_client_uri = properUrl;
        }
      } else {
        results.push({
          id: 'client-reg-3.2.1',
          category: ComplianceCategory.CLIENT_REGISTRATION,
          requirement: 'registration_client_uri is fully qualified URL',
          status: 'pass',
          message: `Valid URL: ${response.registration_client_uri}`,
          timestamp: new Date(),
          indentLevel: 3
        });
      }
    }

    // Create context
    const context: ClientRegistrationContext = {
      method: ClientRegistrationMethod.DYNAMIC_CLIENT_REGISTRATION,
      clientId: response.client_id,
      clientSecret: response.client_secret,
      redirectUri: response.redirect_uris?.[0] || redirectUri,
      registrationAccessToken: response.registration_access_token,
      registrationClientUri: response.registration_client_uri
    };

    return { results, context };
  } catch (error) {
    // Extract debug info and validation errors if available
    const debugInfo = (error as any).debugInfo;
    const validationErrors = (error as any).validationErrors;

    // Build detailed error message
    let errorMessage = `Registration failed: ${error instanceof Error ? error.message : String(error)}`;

    // Add validation error details if available
    if (validationErrors && validationErrors.errors) {
      const zodErrors = validationErrors.errors.map((e: any) => ({
        validation: e.validation,
        code: e.code,
        message: e.message,
        path: e.path
      }));
      errorMessage += `\n\nValidation errors: ${JSON.stringify(zodErrors, null, 2)}`;
    }

    results.push({
      id: 'client-reg-3.error',
      category: ComplianceCategory.CLIENT_REGISTRATION,
      requirement: 'Dynamic Client Registration',
      status: 'fail',
      message: errorMessage,
      timestamp: new Date(),
      indentLevel: 2,
      details: validationErrors
        ? {
            validationErrors: validationErrors.errors?.map((e: any) => ({
              validation: e.validation,
              code: e.code,
              message: e.message,
              path: e.path
            }))
          }
        : undefined,
      debug: debugInfo,
      ...TEST_METADATA['dcr-3.2']
    });
    return { results };
  }
}
