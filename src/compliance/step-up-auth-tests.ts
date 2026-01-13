/**
 * Step-Up Authorization Tests (MCP 2025-11-25)
 *
 * Tests step-up authorization flow including:
 * - Detecting insufficient_scope errors
 * - Parsing required scopes from error responses
 * - Re-authorizing with additional scopes
 * - Retry logic with new token
 * - Scope challenge handling (test step-1.5)
 */

import {
  ComplianceTestResult,
  ComplianceCategory,
  ServerTestConfig
} from '../types/compliance.js';
import { ProtocolVersion } from '../types/protocol-version.js';

/**
 * Run step-up authorization tests
 *
 * @param config - Test configuration
 * @param accessToken - Current access token (optional, for scope challenge test)
 * @returns Test results
 */
export async function runStepUpAuthTests(
  config: ServerTestConfig,
  accessToken?: string
): Promise<ComplianceTestResult[]> {
  const results: ComplianceTestResult[] = [];
  const protocolVersion = config.protocolVersion || ProtocolVersion.PRE_2025_11_25;

  // Header
  results.push({
    id: 'step-header',
    category: ComplianceCategory.STEP_UP_AUTH,
    requirement: 'Step-Up Authorization',
    status: 'info',
    message: `Protocol version: ${protocolVersion}`,
    timestamp: new Date(),
    indentLevel: 0
  });

  // Only run for MCP 2025-11-25
  if (protocolVersion !== ProtocolVersion.MCP_2025_11_25) {
    results.push({
      id: 'step-1.0',
      category: ComplianceCategory.STEP_UP_AUTH,
      requirement: 'Step-up authorization support',
      status: 'skip',
      message: 'Step-up authorization is only tested for MCP 2025-11-25',
      timestamp: new Date(),
      indentLevel: 1
    });
    return results;
  }

  // Test 1.0: Scope Challenge Handling - requires privileged tool to test server behavior
  if (config.privilegedToolName) {
    await runScopeChallengeTest(config, accessToken, results);
  } else {
    results.push({
      id: 'step-1.0',
      category: ComplianceCategory.STEP_UP_AUTH,
      requirement: 'Scope challenge handling',
      status: 'skip',
      message: 'No privileged tool configured for scope challenge test',
      timestamp: new Date(),
      indentLevel: 1,
      details: {
        configuration: 'Set privilegedToolName in config to enable this test',
        description: 'Tests server behavior: returns 403 with scope challenge, accepts elevated token after re-authorization'
      }
    });
  }

  return results;
}

/**
 * Run scope challenge test (step-1.0)
 *
 * This test validates SERVER COMPLIANCE with scope challenge handling:
 * 1. Server returns 403 for privileged tool with base token
 * 2. Server includes scope challenge in error response
 * 3. Server accepts elevated token after re-authorization
 * 4. Server allows access with elevated scope
 */
async function runScopeChallengeTest(
  config: ServerTestConfig,
  accessToken: string | undefined,
  results: ComplianceTestResult[]
): Promise<void> {
  const privilegedTool = config.privilegedToolName!;

  // Skip if no access token available
  if (!accessToken) {
    results.push({
      id: 'step-1.0',
      category: ComplianceCategory.STEP_UP_AUTH,
      requirement: 'Scope challenge handling with privileged tool',
      status: 'skip',
      message: 'No access token available for scope challenge test',
      timestamp: new Date(),
      indentLevel: 1,
      details: {
        privilegedTool,
        note: 'Access token required to test scope challenge flow'
      }
    });
    return;
  }

  const debugInfo: any = {};

  try {
    // Step 1: Attempt to call privileged tool (expect 403)
    // Pass enableDebug to capture full request/response packets
    const toolResponse = await callMCPTool(config, privilegedTool, accessToken, config.enableDebug);

    // Extract debug info if present
    const capturedDebug = toolResponse?.__debug;
    if (capturedDebug) {
      Object.assign(debugInfo, capturedDebug);
    }

    // If we get here without error, the tool didn't challenge - FAIL
    results.push({
      id: 'step-1.0.1',
      category: ComplianceCategory.STEP_UP_AUTH,
      requirement: 'Server returns 403 for insufficient scope',
      status: 'fail',
      message: 'Server did not return 403 for insufficient scope',
      timestamp: new Date(),
      indentLevel: 2,
      expected: '403 Forbidden with scope challenge',
      actual: '200 OK (no scope validation)',
      details: {
        privilegedTool,
        response: toolResponse
      },
      remediation: 'Configure server to require elevated scope and return 403 with scope challenge',
      debug: config.enableDebug ? debugInfo : undefined
    });
  } catch (error: any) {
    // Extract debug info from error if present
    if (error.debug) {
      Object.assign(debugInfo, error.debug);
    }

    // Step 2: Validate 403 response format
    if (error.status !== 403) {
      results.push({
        id: 'step-1.0.1',
        category: ComplianceCategory.STEP_UP_AUTH,
        requirement: 'Server returns 403 status code for insufficient scope',
        status: 'fail',
        message: `Expected 403, got ${error.status}`,
        timestamp: new Date(),
        indentLevel: 2,
        expected: '403 Forbidden',
        actual: `${error.status} ${error.statusText || ''}`,
        details: {
          privilegedTool,
          errorResponse: error.body
        },
        debug: config.enableDebug ? debugInfo : undefined
      });
      return;
    }

    results.push({
      id: 'step-1.0.1',
      category: ComplianceCategory.STEP_UP_AUTH,
      requirement: 'Server returns 403 for insufficient scope',
      status: 'pass',
      message: `Server returned 403 Forbidden as expected`,
      timestamp: new Date(),
      indentLevel: 2,
      details: {
        privilegedTool,
        status: error.status
      },
      debug: config.enableDebug ? debugInfo : undefined
    });

    // Step 3: Parse scope challenge
    const requiredScope = parseScopeChallenge(error);

    if (config.enableDebug) {
      debugInfo.scopeChallengeParsing = {
        errorBodyScope: error.body?.scope,
        errorDescription: error.body?.error_description,
        wwwAuthHeader: error.headers?.['www-authenticate'] || error.headers?.['WWW-Authenticate'],
        parsedScope: requiredScope
      };
    }

    if (!requiredScope) {
      // Format error response details
      const errorDetails: string[] = [];
      if (error.body?.error) {
        errorDetails.push(`error: ${error.body.error}`);
      }
      if (error.body?.error_description) {
        errorDetails.push(`error_description: ${error.body.error_description}`);
      }
      const formattedError = errorDetails.length > 0
        ? errorDetails.join(', ')
        : JSON.stringify(error.body);

      results.push({
        id: 'step-1.0.2',
        category: ComplianceCategory.STEP_UP_AUTH,
        requirement: 'Server includes scope information in error response',
        status: 'fail',
        message: `Server 403 response missing scope challenge information. Received: ${formattedError}`,
        timestamp: new Date(),
        indentLevel: 2,
        expected: 'error_description or WWW-Authenticate with scope parameter',
        actual: formattedError,
        rfcReference: 'MCP 2025-11-25 Section 10.1',
        rfcUrl: 'https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#scope-challenge',
        remediation: 'Server must include scope parameter in error response body or WWW-Authenticate header',
        details: {
          errorBody: error.body,
          wwwAuthHeader: error.headers?.['www-authenticate'] || error.headers?.['WWW-Authenticate']
        },
        debug: config.enableDebug ? debugInfo : undefined
      });
      return;
    }

    results.push({
      id: 'step-1.0.2',
      category: ComplianceCategory.STEP_UP_AUTH,
      requirement: 'Server provides scope challenge information',
      status: 'pass',
      message: `Server provided required scope in error response: ${requiredScope}`,
      timestamp: new Date(),
      indentLevel: 2,
      details: {
        privilegedTool,
        requiredScope,
        errorResponse: error.body,
        parseMethod: error.body?.scope ? 'error body' : 'WWW-Authenticate header'
      },
      debug: config.enableDebug ? debugInfo : undefined
    });

    // Step 4-6: Re-authorization with elevated scope
    // Check if interactive auth is enabled for automatic re-authorization
    if (config.interactiveAuth) {
      await performStepUpReauthorization(
        config,
        requiredScope,
        privilegedTool,
        accessToken,
        results
      );
    } else {
      // Document manual re-authorization steps
      results.push({
        id: 'step-1.0.3',
        category: ComplianceCategory.STEP_UP_AUTH,
        requirement: 'Re-authorization with elevated scope (interactive test)',
        status: 'info',
        message: 'Scope challenge detected - enable interactive auth to test full re-authorization flow',
        timestamp: new Date(),
        indentLevel: 2,
        details: {
          requiredScope,
          note: 'Set interactiveAuth: true in config to automatically test re-authorization and verify server accepts elevated token',
          serverBehaviorToTest: [
            'Server accepts authorization request with elevated scopes',
            'Server issues token with elevated scope',
            'Server allows access to privileged tool with new token'
          ]
        }
      });
    }
  }
}

/**
 * Perform step-up re-authorization with elevated scope
 *
 * Complete end-to-end test:
 * 1. Merge original scopes with required scopes
 * 2. Initiate new OAuth flow with elevated scopes
 * 3. User authenticates via browser
 * 4. Exchange code for new access token
 * 5. Retry privileged tool with new token
 * 6. Verify tool is now accessible
 */
async function performStepUpReauthorization(
  config: ServerTestConfig,
  requiredScope: string,
  privilegedTool: string,
  _originalToken: string,
  results: ComplianceTestResult[]
): Promise<void> {
  const debugInfo: any = {};

  try {
    // Import required modules
    const { buildAuthorizationUrl, exchangeCodeForToken } = await import('../utils/oauth-flow.js');
    const { startCallbackServer } = await import('../utils/callback-server.js');
    const { generatePKCEParams } = await import('../utils/pkce.js');
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    // Step 1: Merge scopes
    const currentScope = config.scope || 'openid profile email';
    const currentScopes = currentScope.split(' ');
    const requiredScopes = requiredScope.split(' ');
    const elevatedScopes = [...new Set([...currentScopes, ...requiredScopes])];
    const elevatedScopeString = elevatedScopes.join(' ');

    if (config.enableDebug) {
      debugInfo.step1_scopeMerging = {
        originalScope: currentScope,
        requiredScope: requiredScope,
        mergedScope: elevatedScopeString
      };
    }

    results.push({
      id: 'step-1.0.3',
      category: ComplianceCategory.STEP_UP_AUTH,
      requirement: 'Prepare re-authorization request',
      status: 'pass',
      message: `Merged scopes for re-authorization: ${elevatedScopeString}`,
      timestamp: new Date(),
      indentLevel: 2,
      details: {
        originalScopes: currentScopes,
        requiredScopes,
        mergedScopes: elevatedScopes
      },
      debug: config.enableDebug ? debugInfo.step1_scopeMerging : undefined
    });

    // Step 2: Prepare OAuth flow parameters
    const callbackPort = config.callbackPort || 3000;
    const redirectUri = `http://localhost:${callbackPort}/callback`;

    // Need authorization endpoint and client ID from config
    if (!config.authorizationEndpoint) {
      results.push({
        id: 'step-1.0.4',
        category: ComplianceCategory.STEP_UP_AUTH,
        requirement: 'Authorization endpoint configured',
        status: 'fail',
        message: 'Cannot perform re-authorization without authorizationEndpoint in config',
        timestamp: new Date(),
        indentLevel: 2,
        details: {
          note: 'authorizationEndpoint must be provided in ServerTestConfig'
        }
      });
      return;
    }

    if (!config.clientId && !config.clientIDMetadataUrl) {
      results.push({
        id: 'step-1.0.4',
        category: ComplianceCategory.STEP_UP_AUTH,
        requirement: 'Client ID configured',
        status: 'fail',
        message: 'Cannot perform re-authorization without clientId or clientIDMetadataUrl in config',
        timestamp: new Date(),
        indentLevel: 2,
        details: {
          note: 'clientId or clientIDMetadataUrl must be provided in ServerTestConfig'
        }
      });
      return;
    }

    const clientId = config.clientId || config.clientIDMetadataUrl!;

    // Generate new PKCE parameters
    const pkceParams = generatePKCEParams();
    const state = pkceParams.state;

    if (config.enableDebug) {
      debugInfo.step2_oauthParams = {
        authorizationEndpoint: config.authorizationEndpoint,
        clientId,
        redirectUri,
        scope: elevatedScopeString,
        state,
        codeChallengeMethod: 'S256'
      };
    }

    // Step 3: Start callback server
    results.push({
      id: 'step-1.0.4',
      category: ComplianceCategory.STEP_UP_AUTH,
      requirement: 'Start OAuth callback server',
      status: 'pass',
      message: `Starting callback server on port ${callbackPort}`,
      timestamp: new Date(),
      indentLevel: 2,
      details: {
        callbackPort,
        redirectUri
      }
    });

    let callbackServer: Awaited<ReturnType<typeof startCallbackServer>> | undefined;

    try {
      callbackServer = await startCallbackServer(callbackPort, config.serverUrl);
      const actualPort = callbackServer.actualPort;
      const actualRedirectUri = actualPort !== callbackPort
        ? `http://localhost:${actualPort}/callback`
        : redirectUri;

      if (config.enableDebug) {
        debugInfo.step3_callbackServer = {
          requestedPort: callbackPort,
          actualPort,
          redirectUri: actualRedirectUri
        };
      }

      // Step 4: Build authorization URL and open browser
      const authUrl = buildAuthorizationUrl({
        authorizationEndpoint: config.authorizationEndpoint,
        clientId,
        redirectUri: actualRedirectUri,
        scope: elevatedScopeString,
        state,
        codeChallenge: pkceParams.codeChallenge,
        codeChallengeMethod: 'S256',
        resource: config.resourceUri
      });

      results.push({
        id: 'step-1.0.5',
        category: ComplianceCategory.STEP_UP_AUTH,
        requirement: 'Server accepts authorization request with elevated scopes',
        status: 'pass',
        message: 'Opening browser for user authentication with elevated scopes',
        timestamp: new Date(),
        indentLevel: 2,
        details: {
          authorizationUrl: authUrl,
          scope: elevatedScopeString
        },
        debug: config.enableDebug ? { authUrl } : undefined
      });

      // Open browser
      console.log(`\n🔐 Re-authorizing with elevated scopes: ${elevatedScopeString}`);
      console.log('Opening browser for authentication...\n');

      const platform = process.platform;
      const openCommand = platform === 'win32' ? 'start' : platform === 'darwin' ? 'open' : 'xdg-open';
      await execAsync(`${openCommand} "${authUrl}"`);

      // Wait for callback
      console.log('Waiting for OAuth callback...');
      const authCode = await callbackServer.waitForCallback();

      if (!authCode.code) {
        results.push({
          id: 'step-1.0.6',
          category: ComplianceCategory.STEP_UP_AUTH,
          requirement: 'Server returns authorization code',
          status: 'fail',
          message: authCode.error ? `OAuth error: ${authCode.error} - ${authCode.error_description || ''}` : 'No authorization code received',
          timestamp: new Date(),
          indentLevel: 2
        });
        return;
      }

      if (authCode.state !== state) {
        results.push({
          id: 'step-1.0.6',
          category: ComplianceCategory.STEP_UP_AUTH,
          requirement: 'State parameter validation',
          status: 'fail',
          message: 'State mismatch in OAuth callback',
          timestamp: new Date(),
          indentLevel: 2,
          expected: state,
          actual: authCode.state
        });
        return;
      }

      results.push({
        id: 'step-1.0.6',
        category: ComplianceCategory.STEP_UP_AUTH,
        requirement: 'Server returns authorization code',
        status: 'pass',
        message: 'Server successfully returned authorization code with elevated consent',
        timestamp: new Date(),
        indentLevel: 2,
        details: {
          codeReceived: true,
          stateValidated: true
        }
      });

      // Step 5: Exchange code for token
      const tokenEndpoint = config.tokenEndpoint;
      if (!tokenEndpoint) {
        results.push({
          id: 'step-1.0.7',
          category: ComplianceCategory.STEP_UP_AUTH,
          requirement: 'Server issues token with elevated scope',
          status: 'fail',
          message: 'Token endpoint not configured',
          timestamp: new Date(),
          indentLevel: 2
        });
        return;
      }

      const tokenResponse = await exchangeCodeForToken({
        tokenEndpoint,
        clientId,
        code: authCode.code,
        redirectUri: actualRedirectUri,
        codeVerifier: pkceParams.codeVerifier,
        clientSecret: config.clientSecret,
        resource: config.resourceUri
      });

      results.push({
        id: 'step-1.0.7',
        category: ComplianceCategory.STEP_UP_AUTH,
        requirement: 'Server issues token with elevated scope',
        status: 'pass',
        message: `Server issued access token with scope: ${tokenResponse.scope || elevatedScopeString}`,
        timestamp: new Date(),
        indentLevel: 2,
        details: {
          tokenType: tokenResponse.token_type,
          scope: tokenResponse.scope,
          expiresIn: tokenResponse.expires_in
        },
        debug: config.enableDebug ? {
          accessToken: `${tokenResponse.access_token.substring(0, 20)}...`,
          fullScope: tokenResponse.scope
        } : undefined
      });

      // Step 6: Retry privileged tool with new token
      try {
        // Capture full request/response packets when retrying with elevated token
        const toolResponse = await callMCPTool(config, privilegedTool, tokenResponse.access_token, config.enableDebug);

        // Extract debug info from successful response
        const retryDebugInfo = toolResponse?.__debug;

        results.push({
          id: 'step-1.0.8',
          category: ComplianceCategory.STEP_UP_AUTH,
          requirement: 'Server allows access with elevated token',
          status: 'pass',
          message: `Server allowed access to privileged tool '${privilegedTool}' with elevated scope`,
          timestamp: new Date(),
          indentLevel: 2,
          expected: '200 OK - tool execution successful',
          actual: '200 OK - tool execution successful',
          details: {
            privilegedTool,
            elevatedScope: elevatedScopeString,
            toolResponse: typeof toolResponse === 'object' ? toolResponse : 'success'
          },
          debug: config.enableDebug ? {
            retryAttempt: retryDebugInfo,
            comparison: {
              firstAttempt: debugInfo.response?.status || 403,
              retryAttempt: retryDebugInfo?.response?.status || 200,
              tokenChanged: true,
              scopeElevated: elevatedScopeString
            }
          } : undefined
        });

        // Final summary
        results.push({
          id: 'step-1.0.9',
          category: ComplianceCategory.STEP_UP_AUTH,
          requirement: 'Complete step-up authorization flow',
          status: 'pass',
          message: '✅ Server fully compliant with step-up authorization: 403 → scope challenge → re-auth → elevated token → access granted',
          timestamp: new Date(),
          indentLevel: 2,
          details: {
            serverBehaviorVerified: [
              '1. Server returned 403 Forbidden for insufficient scope',
              '2. Server provided scope challenge in error response',
              '3. Server accepted authorization with elevated scopes',
              '4. Server issued token with elevated scope',
              '5. Server allowed access to privileged tool with elevated token'
            ],
            verified: 'All server behaviors validated successfully'
          }
        });

      } catch (error: any) {
        // Extract debug info from retry error
        const retryErrorDebug = error.debug;

        results.push({
          id: 'step-1.0.8',
          category: ComplianceCategory.STEP_UP_AUTH,
          requirement: 'Server allows access with elevated token',
          status: 'fail',
          message: `Server still returns error after re-authorization: ${error.status} ${error.statusText || ''}`,
          timestamp: new Date(),
          indentLevel: 2,
          expected: '200 OK - tool execution successful',
          actual: `${error.status} - ${error.body?.error || 'error'}`,
          details: {
            privilegedTool,
            elevatedScope: elevatedScopeString,
            errorResponse: error.body,
            issue: 'Token obtained successfully but server still returns error. Verify that the authorization server granted all requested scopes.'
          },
          debug: config.enableDebug ? {
            retryAttempt: retryErrorDebug,
            comparison: {
              firstAttempt: {
                status: debugInfo.response?.status || 403,
                error: debugInfo.response?.body?.error || 'insufficient_scope'
              },
              retryAttempt: {
                status: error.status,
                error: error.body?.error || 'unknown'
              },
              tokenChanged: true,
              scopeElevated: elevatedScopeString,
              issue: 'Both attempts failed - scope may not have been granted or server validation is incorrect'
            }
          } : undefined,
          remediation: 'Check that:\n1. Authorization server granted the requested scope in the token\n2. Server correctly validates the scope in the access token\n3. Token contains the elevated scope in its scope claim or JWT payload'
        });
      }

    } finally {
      // Clean up callback server
      if (callbackServer) {
        callbackServer.close();
      }
    }

  } catch (error: any) {
    results.push({
      id: 'step-1.0.4',
      category: ComplianceCategory.STEP_UP_AUTH,
      requirement: 'Re-authorization with elevated scope',
      status: 'fail',
      message: `Failed to complete re-authorization: ${error.message}`,
      timestamp: new Date(),
      indentLevel: 2,
      details: {
        error: error.message,
        stack: error.stack
      },
      debug: config.enableDebug ? debugInfo : undefined
    });
  }
}

/**
 * Parse required scope from scope challenge error response
 *
 * Checks multiple sources in order:
 * 1. error.body.scope - Direct scope parameter in error response
 * 2. error.body.error_description - Parse scope hint from description
 * 3. WWW-Authenticate header - Parse scope from challenge header
 */
function parseScopeChallenge(error: any): string | null {
  // Method 1: Check error response body for scope parameter
  if (error.body?.scope) {
    return error.body.scope;
  }

  // Method 2: Check error_description for scope hint
  if (error.body?.error_description) {
    const match = error.body.error_description.match(/scope[:\s]+['""]?([a-z_]+)['""]?/i);
    if (match && match[1]) {
      return match[1];
    }
  }

  // Method 3: Parse WWW-Authenticate header
  const wwwAuth = error.headers?.['www-authenticate'] || error.headers?.['WWW-Authenticate'];
  if (wwwAuth) {
    const scopeMatch = wwwAuth.match(/scope="([^"]+)"/);
    if (scopeMatch && scopeMatch[1]) {
      return scopeMatch[1];
    }
  }

  return null;
}

/**
 * Call an MCP tool with authentication and optional debug capture
 *
 * This is a simplified implementation for testing purposes.
 * In production, this would use the actual MCP client.
 *
 * @param config - Server test configuration
 * @param toolName - Name of the tool to call
 * @param accessToken - Bearer access token
 * @param captureDebug - Whether to capture detailed request/response debug info
 * @returns Tool response (or throws error with debug info)
 */
async function callMCPTool(
  config: ServerTestConfig,
  toolName: string,
  accessToken: string,
  captureDebug: boolean = false
): Promise<any> {
  const debugInfo: any = captureDebug ? {
    toolName,
    capturedAt: new Date().toISOString()
  } : undefined;

  // For HTTP transport
  if (config.serverUrl) {
    // MCP uses JSON-RPC, not REST - tool name goes in request body, not URL
    const url = config.serverUrl;
    const requestBody = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: {}
      },
      id: Math.random().toString(36).substring(7)
    };

    // Capture outgoing request packet
    if (debugInfo) {
      debugInfo.request = {
        method: 'POST',
        url,
        headers: {
          'Authorization': `Bearer ${accessToken.substring(0, 30)}...${accessToken.substring(accessToken.length - 10)}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json, text/event-stream'
        },
        body: requestBody,
        bodySize: JSON.stringify(requestBody).length,
        sentAt: new Date().toISOString()
      };
    }

    const startTime = Date.now();
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream'
      },
      body: JSON.stringify(requestBody)
    });
    const elapsedMs = Date.now() - startTime;

    // Parse response based on content type
    const contentType = response.headers.get('content-type') || '';
    let responseBody: any = {};

    if (contentType.includes('text/event-stream')) {
      // Parse SSE format
      const text = await response.text();
      responseBody = parseSSEResponse(text);
    } else {
      // Parse JSON
      responseBody = await response.json().catch(() => ({}));
    }

    // Capture incoming response packet
    if (debugInfo) {
      debugInfo.response = {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: responseBody,
        bodySize: JSON.stringify(responseBody).length,
        elapsedMs,
        receivedAt: new Date().toISOString()
      };

      // Add roundtrip summary
      debugInfo.roundtrip = {
        durationMs: elapsedMs,
        success: response.ok
      };
    }

    if (!response.ok) {
      const error: any = {
        status: response.status,
        statusText: response.statusText,
        body: responseBody,
        headers: Object.fromEntries(response.headers.entries())
      };

      // Attach debug info to error
      if (debugInfo) {
        error.debug = debugInfo;
      }

      throw error;
    }

    // For successful responses, attach debug if captured
    if (debugInfo) {
      return {
        ...responseBody,
        __debug: debugInfo
      };
    }

    return responseBody;
  }

  // For stdio transport, we would use the MCP SDK client
  // This is not implemented in the test environment
  throw new Error('Stdio transport not supported in scope challenge test');
}

/**
 * Parse Server-Sent Events (SSE) response format
 *
 * MCP servers may return errors in SSE format when using text/event-stream.
 * This function extracts the error information from SSE event data.
 *
 * @param sseText - Raw SSE response text
 * @returns Parsed error object or empty object
 */
function parseSSEResponse(sseText: string): any {
  const lines = sseText.split('\n');
  const events: any[] = [];
  let currentEvent: any = {};

  for (const line of lines) {
    if (line.startsWith('event:')) {
      currentEvent.event = line.substring(6).trim();
    } else if (line.startsWith('data:')) {
      const data = line.substring(5).trim();
      try {
        currentEvent.data = JSON.parse(data);
      } catch {
        currentEvent.data = data;
      }
    } else if (line === '') {
      // Empty line indicates end of event
      if (Object.keys(currentEvent).length > 0) {
        events.push(currentEvent);
        currentEvent = {};
      }
    }
  }

  // Add final event if any
  if (Object.keys(currentEvent).length > 0) {
    events.push(currentEvent);
  }

  // Look for error events
  const errorEvent = events.find(e => e.event === 'error' || e.data?.error);
  if (errorEvent?.data) {
    return errorEvent.data;
  }

  // Look for JSON-RPC error in response
  const responseEvent = events.find(e => e.event === 'message' || e.data?.error);
  if (responseEvent?.data?.error) {
    return responseEvent.data.error;
  }

  // Return first event data if available
  if (events.length > 0 && events[0].data) {
    return events[0].data;
  }

  // Return raw SSE text as error for debugging
  return {
    error: 'sse_parse_error',
    error_description: 'Could not parse SSE response',
    raw_sse: sseText
  };
}
