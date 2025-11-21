/**
 * MCP Authorization Flow Compliance Tester
 * Tests MCP server compliance with RFC 9728, RFC 8414, RFC 7591, and OAuth 2.1
 */

import {
  ComplianceTestResult,
  ComplianceTestSuite,
  ComplianceCategory,
  ServerTestConfig,
} from '../types/compliance.js';
import { TEST_METADATA } from './test-metadata.js';
import { generatePKCEParams } from '../utils/pkce.js';
import { startCallbackServer } from '../utils/callback-server.js';
import { exec } from 'child_process';
import * as jose from 'jose';

export class MCPComplianceTester {
  private config: ServerTestConfig;
  private results: ComplianceTestResult[] = [];
  private cache: Map<string, unknown> = new Map();

  constructor(config: ServerTestConfig) {
    this.config = {
      timeout: 30000,
      ...config,
    };
  }

  async runAllTests(): Promise<ComplianceTestSuite> {
    const startTime = new Date();
    this.results = [];
    this.cache.clear();

    // Run tests in order (some depend on previous results)
    await this.testProtectedResourceMetadata();
    await this.testAuthorizationServerDiscovery();

    if (!this.config.skipDCR) {
      await this.testDynamicClientRegistration();
    }

    if (!this.config.skipOAuthFlow) {
      await this.testOAuthFlow();
    }

    const endTime = new Date();

    return {
      serverUrl: this.config.serverUrl,
      startTime,
      endTime,
      results: this.results,
      summary: this.calculateSummary(),
    };
  }

  private calculateSummary() {
    return {
      total: this.results.length,
      passed: this.results.filter(r => r.status === 'pass').length,
      failed: this.results.filter(r => r.status === 'fail').length,
      skipped: this.results.filter(r => r.status === 'skip').length,
      pending: this.results.filter(r => r.status === 'pending').length,
    };
  }

  private addResult(result: Omit<ComplianceTestResult, 'timestamp'>) {
    // Add RFC metadata if available and not already specified
    const metadata = TEST_METADATA[result.id];
    const enrichedResult: ComplianceTestResult = {
      ...result,
      timestamp: new Date(),
    };

    if (metadata && result.status === 'fail') {
      enrichedResult.rfcReference = enrichedResult.rfcReference || metadata.rfcReference;
      enrichedResult.rfcUrl = enrichedResult.rfcUrl || metadata.rfcUrl;
      enrichedResult.expected = enrichedResult.expected || metadata.expected;
      enrichedResult.remediation = enrichedResult.remediation || metadata.remediation;
    }

    this.results.push(enrichedResult);
  }

  async runSingleTest(testId: string): Promise<ComplianceTestResult | null> {
    // Run a single test by ID - useful for retrying failed tests
    this.results = [];
    this.cache.clear();

    // Map test IDs to their test functions
    if (testId.startsWith('prm-')) {
      await this.testProtectedResourceMetadata();
    } else if (testId.startsWith('as-')) {
      await this.testProtectedResourceMetadata(); // Need PRM first
      await this.testAuthorizationServerDiscovery();
    } else if (testId.startsWith('dcr-')) {
      await this.testProtectedResourceMetadata();
      await this.testAuthorizationServerDiscovery();
      await this.testDynamicClientRegistration();
    } else if (testId.startsWith('oauth-')) {
      await this.testProtectedResourceMetadata();
      await this.testAuthorizationServerDiscovery();
      await this.testOAuthFlow();
    }

    return this.results.find(r => r.id === testId) || null;
  }

  // ==================================================================
  // 1. Protected Resource Metadata Discovery (RFC 9728)
  // ==================================================================

  private async testProtectedResourceMetadata() {
    const category = ComplianceCategory.PROTECTED_RESOURCE_METADATA;

    // Test 1.0: HTTPS transport required (except localhost)
    const serverUrl = new URL(this.config.serverUrl);
    const isLocalhost = serverUrl.hostname === 'localhost' ||
                       serverUrl.hostname === '127.0.0.1' ||
                       serverUrl.hostname === '::1' ||
                       serverUrl.hostname.endsWith('.local');
    const isHttps = serverUrl.protocol === 'https:';

    if (!isHttps && !isLocalhost) {
      this.addResult({
        id: 'prm-1.0',
        category,
        requirement: 'HTTPS transport required for production (REQUIRED)',
        status: 'fail',
        message: 'Server is using HTTP protocol for a non-localhost URL - HTTPS is required in production',
        expected: 'https:// protocol for non-localhost URLs',
        actual: serverUrl.protocol,
        details: {
          serverUrl: this.config.serverUrl,
          protocol: serverUrl.protocol,
          hostname: serverUrl.hostname
        },
        rfcReference: 'RFC 6749 Section 3.1, RFC 8414 Section 2',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1',
        remediation: 'Use HTTPS for all production OAuth servers. HTTP is only acceptable for localhost/development.',
      });
    } else if (!isHttps && isLocalhost) {
      this.addResult({
        id: 'prm-1.0',
        category,
        requirement: 'HTTPS transport required for production (REQUIRED)',
        status: 'warning',
        message: 'Server is using HTTP on localhost - acceptable for development only',
        expected: 'https:// protocol (http:// acceptable for localhost)',
        actual: serverUrl.protocol,
        details: {
          serverUrl: this.config.serverUrl,
          protocol: serverUrl.protocol,
          hostname: serverUrl.hostname
        },
        rfcReference: 'RFC 6749 Section 3.1',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1',
      });
    } else {
      this.addResult({
        id: 'prm-1.0',
        category,
        requirement: 'HTTPS transport required for production (REQUIRED)',
        status: 'pass',
        message: 'Server is using HTTPS protocol',
        details: {
          serverUrl: this.config.serverUrl,
          protocol: serverUrl.protocol
        },
        rfcReference: 'RFC 6749 Section 3.1',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1',
      });
    }

    // Test 1.1: Initial request returns 401
    try {
      // Send a proper MCP initialize request
      const mcpRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: {
            name: 'MCP Compliance Tester',
            version: '0.1.0',
          },
        },
      };

      const response = await this.fetchWithTimeout(this.config.serverUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(mcpRequest),
      });

      if (response.status === 401) {
        this.addResult({
          id: 'prm-1.1',
          category,
          requirement: 'HTTP 401 response when unauthorized',
          status: 'pass',
          details: { status: response.status },
          rfcReference: 'RFC 9728 Section 2',
          rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-2',
        });

        // Test 1.2: WWW-Authenticate header present
        const wwwAuth = response.headers.get('WWW-Authenticate');
        if (wwwAuth) {
          this.addResult({
            id: 'prm-1.2',
            category,
            requirement: 'WWW-Authenticate header present',
            status: 'pass',
            details: { header: wwwAuth },
          });
          this.cache.set('wwwAuth', wwwAuth);

          // Test 1.3: resource_metadata parameter present
          const hasResourceMetadata = wwwAuth.includes('resource_metadata=');
          this.addResult({
            id: 'prm-1.3',
            category,
            requirement: 'resource_metadata parameter in WWW-Authenticate',
            status: hasResourceMetadata ? 'pass' : 'fail',
            message: hasResourceMetadata
              ? 'resource_metadata parameter found'
              : 'resource_metadata parameter missing (will try fallback URIs)',
          });

          if (hasResourceMetadata) {
            const match = wwwAuth.match(/resource_metadata="?([^",\s]+)"?/);
            if (match) {
              this.cache.set('prmUri', match[1]);
            }
          }
        } else {
          this.addResult({
            id: 'prm-1.2',
            category,
            requirement: 'WWW-Authenticate header present',
            status: 'fail',
            message: 'WWW-Authenticate header not found in 401 response',
            expected: 'WWW-Authenticate header with Bearer scheme',
            actual: 'No WWW-Authenticate header',
            rfcReference: 'RFC 9728 Section 2',
            rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-2',
            remediation: 'Add WWW-Authenticate header to 401 response: WWW-Authenticate: Bearer resource_metadata="https://your-server/.well-known/oauth-protected-resource"',
          });
          this.addResult({
            id: 'prm-1.3',
            category,
            requirement: 'resource_metadata parameter in WWW-Authenticate',
            status: 'skip',
            message: 'Skipped due to missing WWW-Authenticate header',
          });
        }
      } else {
        this.addResult({
          id: 'prm-1.1',
          category,
          requirement: 'HTTP 401 response when unauthorized',
          status: 'fail',
          message: `Server returned HTTP ${response.status} instead of 401`,
          expected: 'HTTP 401 Unauthorized',
          actual: `HTTP ${response.status}`,
          details: { status: response.status },
          rfcReference: 'RFC 9728 Section 2',
          rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-2',
          remediation: 'Configure your MCP server to return HTTP 401 when an unauthenticated request is made to a protected resource',
        });
        // Skip remaining tests if 401 not returned
        this.addResult({
          id: 'prm-1.2',
          category,
          requirement: 'WWW-Authenticate header present',
          status: 'skip',
          message: 'Skipped due to missing 401 response',
        });
        this.addResult({
          id: 'prm-1.3',
          category,
          requirement: 'resource_metadata parameter in WWW-Authenticate',
          status: 'skip',
          message: 'Skipped due to missing 401 response',
        });
      }
    } catch (error) {
      this.addResult({
        id: 'prm-1.1',
        category,
        requirement: 'HTTP 401 response when unauthorized',
        status: 'fail',
        message: `Request failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }

    // Test 1.4-1.6: Try well-known URIs for PRM
    await this.testPRMWellKnownUris(category);

    // Test 1.7-1.8: Validate PRM content
    await this.testPRMContent(category);
  }

  private async testPRMWellKnownUris(category: ComplianceCategory) {
    const serverUrl = new URL(this.config.serverUrl);
    const baseUrl = `${serverUrl.protocol}//${serverUrl.host}`;
    const serverPath = serverUrl.pathname;

    const prmUri = this.cache.get('prmUri') as string | undefined;
    let prmData: unknown = null;

    // Test 1.4: MCP 4.2.1 - Explicit resource_metadata URI (if provided in WWW-Authenticate)
    if (prmUri) {
      try {
        const response = await this.fetchWithTimeout(prmUri);
        if (response.ok) {
          const data = await response.json();
          this.addResult({
            id: 'prm-1.4',
            category,
            requirement: 'MCP 4.2.1: PRM via resource_metadata URI',
            status: 'pass',
            message: 'Successfully retrieved PRM from URI in WWW-Authenticate header',
            details: { uri: prmUri, data },
            rfcReference: 'MCP Draft 4.2.1 / RFC 9728 Section 2.1',
            rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-2.1',
            indentLevel: 1,
            groupLabel: 'MCP 4.2.1',
          });
          if (!prmData) {
            prmData = data;
            this.cache.set('prmData', data);
          }
        } else {
          this.addResult({
            id: 'prm-1.4',
            category,
            requirement: 'MCP 4.2.1: PRM via resource_metadata URI',
            status: 'fail',
            message: `resource_metadata URI returned HTTP ${response.status}`,
            expected: 'PRM document (JSON with authorization_servers)',
            actual: `HTTP ${response.status}`,
            details: { uri: prmUri },
            rfcReference: 'MCP Draft 4.2.1 / RFC 9728 Section 2.1',
            rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-2.1',
            remediation: `The URI provided in resource_metadata parameter (${prmUri}) should return a valid PRM document.`,
            indentLevel: 1,
            groupLabel: 'MCP 4.2.1',
          });
        }
      } catch (error) {
        this.addResult({
          id: 'prm-1.4',
          category,
          requirement: 'MCP 4.2.1: PRM via resource_metadata URI',
          status: 'fail',
          message: error instanceof Error ? error.message : String(error),
          expected: 'PRM document',
          actual: 'Request failed',
          details: { uri: prmUri, error: String(error) },
          indentLevel: 1,
          groupLabel: 'MCP 4.2.1',
        });
      }
    } else {
      this.addResult({
        id: 'prm-1.4',
        category,
        requirement: 'MCP 4.2.1: PRM via resource_metadata URI',
        status: 'skip',
        message: 'No resource_metadata URI provided in WWW-Authenticate header',
        indentLevel: 1,
        groupLabel: 'MCP 4.2.1',
      });
    }

    // Test 1.5: MCP 4.2.2 - Path A: Well-known URI with server path
    // e.g., https://example.com/.well-known/oauth-protected-resource/public/mcp
    // ALWAYS test this if server has a path, regardless of whether PRM was already found
    if (serverPath && serverPath !== '/') {
      // Normalize serverPath by removing leading slashes/backslashes, then prepend single slash
      const normalizedPath = serverPath.replace(/^[\/\\]+/, '');
      const pathSpecificUri = `${baseUrl}/.well-known/oauth-protected-resource/${normalizedPath}`;
      try {
        const response = await this.fetchWithTimeout(pathSpecificUri);
        if (response.ok) {
          const data = await response.json();
          this.addResult({
            id: 'prm-1.5',
            category,
            requirement: 'MCP 4.2.2 - Path A: Path-specific well-known URI',
            status: 'pass',
            message: 'PRM found at path-specific well-known URI',
            details: { uri: pathSpecificUri, data },
            rfcReference: 'MCP Draft 4.2.2',
            rfcUrl: 'https://spec.modelcontextprotocol.io/specification/draft/basic/authentication/',
            indentLevel: 2,
            groupLabel: 'MCP 4.2.2',
          });
          if (!prmData) {
            prmData = data;
            this.cache.set('prmData', data);
          }
        } else {
          this.addResult({
            id: 'prm-1.5',
            category,
            requirement: 'MCP 4.2.2 - Path A: Path-specific well-known URI',
            status: 'warning',
            message: `Path-specific well-known URI returned HTTP ${response.status}`,
            expected: 'PRM document at path-specific location',
            actual: `HTTP ${response.status}`,
            details: { uri: pathSpecificUri },
            rfcReference: 'MCP Draft 4.2.2',
            rfcUrl: 'https://spec.modelcontextprotocol.io/specification/draft/basic/authentication/',
            indentLevel: 2,
            groupLabel: 'MCP 4.2.2',
          });
        }
      } catch (error) {
        this.addResult({
          id: 'prm-1.5',
          category,
          requirement: 'MCP 4.2.2 - Path A: Path-specific well-known URI',
          status: 'warning',
          message: error instanceof Error ? error.message : String(error),
          details: { uri: pathSpecificUri },
          indentLevel: 2,
          groupLabel: 'MCP 4.2.2',
        });
      }
    } else {
      this.addResult({
        id: 'prm-1.5',
        category,
        requirement: 'MCP 4.2.2 - Path A: Path-specific well-known URI',
        status: 'skip',
        message: 'Server URL has no path component',
        indentLevel: 2,
        groupLabel: 'MCP 4.2.2',
      });
    }

    // Test 1.6: MCP 4.2.2 - Path B: Standard well-known URI at root (RFC 9728)
    // e.g., https://example.com/.well-known/oauth-protected-resource
    // ALWAYS test this, regardless of whether PRM was already found
    {
      const standardUri = `${baseUrl}/.well-known/oauth-protected-resource`;
      try {
        const response = await this.fetchWithTimeout(standardUri);
        if (response.ok) {
          const data = await response.json();
          this.addResult({
            id: 'prm-1.6',
            category,
            requirement: 'MCP 4.2.2 - Path B: Standard well-known URI (root)',
            status: 'pass',
            message: 'PRM found at standard RFC 9728 location',
            details: { uri: standardUri, data },
            rfcReference: 'MCP Draft 4.2.2 / RFC 9728 Section 3',
            rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-3',
            indentLevel: 2,
            groupLabel: 'MCP 4.2.2',
          });
          if (!prmData) {
            prmData = data;
            this.cache.set('prmData', data);
          }
        } else {
          this.addResult({
            id: 'prm-1.6',
            category,
            requirement: 'MCP 4.2.2 - Path B: Standard well-known URI (root)',
            status: 'warning',
            message: `Standard well-known URI returned HTTP ${response.status}`,
            expected: 'PRM document at /.well-known/oauth-protected-resource',
            actual: `HTTP ${response.status}`,
            details: { uri: standardUri },
            rfcReference: 'MCP Draft 4.2.2 / RFC 9728 Section 3',
            rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-3',
            remediation: `Host your Protected Resource Metadata at ${standardUri}. This is the standard location per RFC 9728.`,
            indentLevel: 2,
            groupLabel: 'MCP 4.2.2',
          });
        }
      } catch (error) {
        this.addResult({
          id: 'prm-1.6',
          category,
          requirement: 'MCP 4.2.2 - Path B: Standard well-known URI (root)',
          status: 'warning',
          message: error instanceof Error ? error.message : String(error),
          details: { uri: standardUri },
          indentLevel: 2,
          groupLabel: 'MCP 4.2.2',
        });
      }
    }

    // Test 1.7: MCP 4.2.2 - Path C: Fallback to OAuth AS well-known URI
    // When PRM is not found, try to discover the AS directly
    // ALWAYS test this, regardless of whether PRM was already found
    {
      const oauthAsUri = `${baseUrl}/.well-known/oauth-authorization-server`;
      try {
        const response = await this.fetchWithTimeout(oauthAsUri);
        if (response.ok) {
          const data = await response.json() as Record<string, any>;
          // Check if this is AS metadata (has 'issuer' field) or PRM (has 'authorization_servers')
          const isASMetadata = 'issuer' in data && !('authorization_servers' in data);
          const isPRM = 'authorization_servers' in data;

          if (isPRM) {
            // Found PRM at AS location
            this.addResult({
              id: 'prm-1.7',
              category,
              requirement: 'MCP 4.2.2 - Path C: OAuth AS well-known URI (fallback)',
              status: 'pass',
              message: 'Found PRM at OAuth AS well-known location',
              details: { uri: oauthAsUri, data },
              rfcReference: 'RFC 8414 Section 3',
              rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-3',
              indentLevel: 2,
              groupLabel: 'MCP 4.2.2',
            });
            if (!prmData) {
              prmData = data;
              this.cache.set('prmData', data);
            }
          } else if (isASMetadata) {
            // Found AS metadata directly - this is a valid fallback discovery method
            this.addResult({
              id: 'prm-1.7',
              category,
              requirement: 'MCP 4.2.2 - Path C: OAuth AS well-known URI (fallback)',
              status: 'pass',
              message: 'Successfully discovered AS metadata via OAuth well-known URI',
              details: { uri: oauthAsUri, data },
              rfcReference: 'RFC 8414 Section 3',
              rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-3',
              indentLevel: 2,
              groupLabel: 'MCP 4.2.2',
            });
            // Cache AS URL directly since we found AS metadata
            if ('issuer' in data) {
              this.cache.set('asUrl', data.issuer);
              this.cache.set('asMetadata', data);
            }
          } else {
            // Found something but not sure what it is
            this.addResult({
              id: 'prm-1.7',
              category,
              requirement: 'MCP 4.2.2 - Path C: OAuth AS well-known URI (fallback)',
              status: 'warning',
              message: 'Found metadata but cannot determine type (missing both authorization_servers and issuer)',
              details: { uri: oauthAsUri, data },
              indentLevel: 2,
              groupLabel: 'MCP 4.2.2',
            });
          }
        } else {
          this.addResult({
            id: 'prm-1.7',
            category,
            requirement: 'MCP 4.2.2 - Path C: OAuth AS well-known URI (fallback)',
            status: 'warning',
            message: `OAuth AS well-known URI returned HTTP ${response.status}`,
            actual: `HTTP ${response.status}`,
            details: { uri: oauthAsUri },
            indentLevel: 2,
            groupLabel: 'MCP 4.2.2',
          });
        }
      } catch (error) {
        this.addResult({
          id: 'prm-1.7',
          category,
          requirement: 'MCP 4.2.2 - Path C: OAuth AS well-known URI (fallback)',
          status: 'warning',
          message: error instanceof Error ? error.message : String(error),
          details: { uri: oauthAsUri },
          indentLevel: 2,
          groupLabel: 'MCP 4.2.2',
        });
      }
    }

    // Add overall MCP 4.2.2 status (passes if any of the fallback paths worked)
    const mcp422Results = this.results.filter(r => r.groupLabel === 'MCP 4.2.2');
    const mcp422Passed = mcp422Results.some(r => r.status === 'pass');
    const passedCount = mcp422Results.filter(r => r.status === 'pass').length;

    this.addResult({
      id: 'prm-4.2.2-summary',
      category,
      requirement: 'MCP 4.2.2: Fallback Discovery (at least one path succeeds)',
      status: mcp422Passed ? 'pass' : 'fail',
      message: mcp422Passed
        ? `Discovery successful via fallback method (${passedCount} of ${mcp422Results.length} paths worked)`
        : 'All fallback discovery paths failed',
      indentLevel: 1,
      rfcReference: 'MCP Draft 4.2.2',
      rfcUrl: 'https://spec.modelcontextprotocol.io/specification/draft/basic/authentication/',
    });
  }

  private async testPRMContent(category: ComplianceCategory) {
    const prmData = this.cache.get('prmData') as Record<string, unknown> | undefined;
    const asUrl = this.cache.get('asUrl') as string | undefined;
    const asMetadata = this.cache.get('asMetadata') as Record<string, unknown> | undefined;

    if (!prmData) {
      // Check if we found AS directly (fallback scenario)
      if (asUrl && asMetadata) {
        this.addResult({
          id: 'prm-1.8',
          category,
          requirement: 'PRM contains authorization_servers array (REQUIRED)',
          status: 'warning',
          message: 'PRM not found, but AS was discovered via fallback - tests can continue',
          expected: 'Non-empty authorization_servers array in PRM',
          actual: 'No PRM, but AS discovered directly',
          details: { as_url: asUrl },
          rfcReference: 'RFC 9728 Section 3',
          rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-3',
          remediation: 'The server should provide Protected Resource Metadata per RFC 9728 with an authorization_servers array. However, since the AS was discovered via the fallback method, DCR and OAuth flow tests can continue.',
        });

        // Skip scopes_supported test since we don't have PRM
        this.addResult({
          id: 'prm-1.9',
          category,
          requirement: 'PRM contains scopes_supported (RECOMMENDED)',
          status: 'skip',
          message: 'No PRM available (AS discovered via fallback)',
        });
        return;
      }

      // Neither PRM nor AS found
      this.addResult({
        id: 'prm-1.8',
        category,
        requirement: 'PRM contains authorization_servers array (REQUIRED)',
        status: 'fail',
        message: 'No PRM data could be retrieved from any discovery method',
        expected: 'PRM document with authorization_servers field',
        actual: 'No PRM document found',
        rfcReference: 'RFC 9728 Section 3',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-3',
        remediation: 'Ensure PRM is accessible via at least one of the discovery methods: resource_metadata URI, path-specific well-known URI, or standard well-known URI.',
      });
      this.addResult({
        id: 'prm-1.9',
        category,
        requirement: 'PRM contains scopes_supported (RECOMMENDED)',
        status: 'skip',
        message: 'No PRM data available',
      });
      return;
    }

    // Test 1.8: authorization_servers present
    const hasAuthServers = Array.isArray(prmData.authorization_servers) && prmData.authorization_servers.length > 0;
    this.addResult({
      id: 'prm-1.8',
      category,
      requirement: 'PRM contains authorization_servers array (REQUIRED)',
      status: hasAuthServers ? 'pass' : 'fail',
      message: hasAuthServers ? undefined : 'authorization_servers missing or empty in PRM',
      expected: 'Non-empty authorization_servers array',
      actual: hasAuthServers ? 'Present' : 'Missing or empty',
      details: { authorization_servers: prmData.authorization_servers },
      rfcReference: 'RFC 9728 Section 3',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-3',
      remediation: 'Add an "authorization_servers" array to your PRM containing the issuer identifier(s) of your authorization server(s).\n\nExample:\n{\n  "resource": "https://your-server/mcp",\n  "authorization_servers": ["https://your-auth-server"],\n  "scopes_supported": ["read", "write"]\n}',
    });

    if (hasAuthServers) {
      this.cache.set('asUrl', (prmData.authorization_servers as string[])[0]);
    }

    // Test 1.9: scopes_supported present (RECOMMENDED, not required)
    const hasScopes = Array.isArray(prmData.scopes_supported);
    this.addResult({
      id: 'prm-1.9',
      category,
      requirement: 'PRM contains scopes_supported (RECOMMENDED)',
      status: hasScopes ? 'pass' : 'skip',
      message: hasScopes ? 'scopes_supported present' : 'scopes_supported missing (RECOMMENDED but not required)',
      details: { scopes_supported: prmData.scopes_supported },
      rfcReference: 'RFC 9728 Section 3',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-3',
    });
  }

  // ==================================================================
  // 2. Authorization Server Discovery (RFC 8414)
  // ==================================================================

  private async testAuthorizationServerDiscovery() {
    const category = ComplianceCategory.AS_DISCOVERY;
    const asUrl = this.cache.get('asUrl') as string | undefined;

    if (!asUrl) {
      this.addResult({
        id: 'as-2.1',
        category,
        requirement: 'AS metadata endpoint accessible',
        status: 'skip',
        message: 'No authorization server URL available from PRM',
      });
      return;
    }

    // Test 2.0a: HTTPS transport required for AS (except localhost)
    const asUrlObj = new URL(asUrl);
    const isLocalhost = asUrlObj.hostname === 'localhost' ||
                       asUrlObj.hostname === '127.0.0.1' ||
                       asUrlObj.hostname === '::1' ||
                       asUrlObj.hostname.endsWith('.local');
    const isHttps = asUrlObj.protocol === 'https:';

    if (!isHttps && !isLocalhost) {
      this.addResult({
        id: 'as-2.0a',
        category,
        requirement: 'HTTPS transport required for AS in production (REQUIRED)',
        status: 'fail',
        message: 'Authorization server is using HTTP protocol for a non-localhost URL - HTTPS is required in production',
        expected: 'https:// protocol for non-localhost URLs',
        actual: asUrlObj.protocol,
        details: {
          asUrl,
          protocol: asUrlObj.protocol,
          hostname: asUrlObj.hostname
        },
        rfcReference: 'RFC 6749 Section 3.1, RFC 8414 Section 2',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1',
        remediation: 'Use HTTPS for all production OAuth authorization servers. HTTP is only acceptable for localhost/development.',
      });
    } else if (!isHttps && isLocalhost) {
      this.addResult({
        id: 'as-2.0a',
        category,
        requirement: 'HTTPS transport required for AS in production (REQUIRED)',
        status: 'warning',
        message: 'Authorization server is using HTTP on localhost - acceptable for development only',
        expected: 'https:// protocol (http:// acceptable for localhost)',
        actual: asUrlObj.protocol,
        details: {
          asUrl,
          protocol: asUrlObj.protocol,
          hostname: asUrlObj.hostname
        },
        rfcReference: 'RFC 6749 Section 3.1',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1',
      });
    } else {
      this.addResult({
        id: 'as-2.0a',
        category,
        requirement: 'HTTPS transport required for AS in production (REQUIRED)',
        status: 'pass',
        message: 'Authorization server is using HTTPS protocol',
        details: {
          asUrl,
          protocol: asUrlObj.protocol
        },
        rfcReference: 'RFC 6749 Section 3.1',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1',
      });
    }

    // Test 2.0b: Warn if AS URL has trailing slash (RFC 8414 violation)
    if (asUrl.match(/[\/\\]$/)) {
      this.addResult({
        id: 'as-2.0',
        category,
        requirement: 'AS URL should not have trailing slash',
        status: 'warning',
        message: 'Authorization server URL ends with trailing slash/backslash - this violates RFC 8414 and may cause issues with non-compliant clients',
        expected: 'AS URL without trailing slash (per RFC 8414 Section 3)',
        actual: asUrl,
        details: { asUrl },
        rfcReference: 'RFC 8414 Section 3',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-3',
        remediation: 'Remove the trailing slash from the authorization server URL in the PRM document. RFC 8414 requires that "any terminating \'/\' MUST be removed" before constructing the well-known URI.',
      });
    }

    try {
      // Try multiple discovery methods per RFC 8414
      let metadata: any = null;
      let metadataUrl: string = '';
      let response: Response | null = null;

      // Method 1: Try the URL directly (might already be metadata)
      try {
        response = await this.fetchWithTimeout(asUrl);
        if (response.ok) {
          const data = await response.json();
          // Check if it looks like AS metadata (has issuer field)
          if (data && typeof data === 'object' && 'issuer' in data) {
            metadata = data;
            metadataUrl = asUrl;
          }
        }
      } catch (e) {
        // Continue to next method
      }

      // Method 2: RFC 8414 standard discovery
      // Per RFC 8414 Section 3: Remove terminating "/" and insert "/.well-known/oauth-authorization-server"
      // between the host component and path component
      if (!metadata) {
        try {
          // Parse the AS URL
          const asUrlObj = new URL(asUrl);
          // Remove any terminating slashes from pathname
          let pathname = asUrlObj.pathname.replace(/[\/\\]+$/, '');

          // Insert /.well-known/oauth-authorization-server between host and path
          // If no path (or just /), append to host
          // If there is a path, insert between host and path
          if (!pathname || pathname === '/') {
            metadataUrl = `${asUrlObj.protocol}//${asUrlObj.host}/.well-known/oauth-authorization-server`;
          } else {
            metadataUrl = `${asUrlObj.protocol}//${asUrlObj.host}/.well-known/oauth-authorization-server${pathname}`;
          }

          response = await this.fetchWithTimeout(metadataUrl);
          if (response.ok) {
            metadata = await response.json();
          }
        } catch (e) {
          // Continue to next method
        }
      }

      // Method 3: Append to issuer path (Keycloak-style, non-standard but common)
      // Some servers like Keycloak append /.well-known/oauth-authorization-server to the full issuer path
      // e.g., http://host/realms/name/.well-known/oauth-authorization-server
      if (!metadata) {
        try {
          const appendedUrl = `${asUrl.replace(/[\/\\]+$/, '')}/.well-known/oauth-authorization-server`;
          response = await this.fetchWithTimeout(appendedUrl);
          if (response.ok) {
            metadata = await response.json();
            metadataUrl = appendedUrl;
          }
        } catch (e) {
          // All methods failed
        }
      }

      if (metadata && response?.ok) {
        this.cache.set('asMetadata', metadata);

        this.addResult({
          id: 'as-2.1',
          category,
          requirement: 'AS metadata endpoint accessible',
          status: 'pass',
          details: { url: metadataUrl },
        });

        // Test endpoints per RFC 8414
        const endpoints = [
          { id: 'as-2.2', field: 'registration_endpoint', name: 'registration_endpoint', required: false },
          { id: 'as-2.3', field: 'authorization_endpoint', name: 'authorization_endpoint', required: true },
          { id: 'as-2.4', field: 'token_endpoint', name: 'token_endpoint', required: true },
          { id: 'as-2.5', field: 'scopes_supported', name: 'scopes_supported', required: false },
        ];

        for (const { id, field, name, required } of endpoints) {
          const present = field in metadata && metadata[field];
          this.addResult({
            id,
            category,
            requirement: `AS metadata contains ${name}${required ? ' (REQUIRED)' : ' (OPTIONAL/RECOMMENDED)'}`,
            status: present ? 'pass' : (required ? 'fail' : 'skip'),
            message: present ? undefined : `${name} missing from AS metadata`,
            details: { [field]: metadata[field] },
          });

          // Check HTTPS for endpoint URLs (except scopes_supported which is not a URL)
          if (present && field !== 'scopes_supported' && typeof metadata[field] === 'string') {
            try {
              const endpointUrl = new URL(metadata[field]);
              const isEndpointLocalhost = endpointUrl.hostname === 'localhost' ||
                                         endpointUrl.hostname === '127.0.0.1' ||
                                         endpointUrl.hostname === '::1' ||
                                         endpointUrl.hostname.endsWith('.local');
              const isEndpointHttps = endpointUrl.protocol === 'https:';

              if (!isEndpointHttps && !isEndpointLocalhost) {
                this.addResult({
                  id: `${id}-https`,
                  category,
                  requirement: `${name} uses HTTPS (REQUIRED)`,
                  status: 'fail',
                  message: `${name} is using HTTP protocol for a non-localhost URL - HTTPS is required in production`,
                  expected: 'https:// protocol',
                  actual: endpointUrl.protocol,
                  details: {
                    endpoint: metadata[field],
                    protocol: endpointUrl.protocol,
                    hostname: endpointUrl.hostname
                  },
                  rfcReference: 'RFC 6749 Section 3.1',
                  rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1',
                });
              } else if (!isEndpointHttps && isEndpointLocalhost) {
                this.addResult({
                  id: `${id}-https`,
                  category,
                  requirement: `${name} uses HTTPS (REQUIRED)`,
                  status: 'warning',
                  message: `${name} is using HTTP on localhost - acceptable for development only`,
                  details: {
                    endpoint: metadata[field],
                    protocol: endpointUrl.protocol
                  },
                  rfcReference: 'RFC 6749 Section 3.1',
                  rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1',
                });
              }
            } catch (e) {
              // Invalid URL - will be caught by other validation
            }
          }
        }
      } else {
        // Construct the attempted URIs for error reporting
        let rfc8414Uri: string;
        let keycloakStyleUri: string;
        try {
          const asUrlObj = new URL(asUrl);
          let pathname = asUrlObj.pathname.replace(/[\/\\]+$/, '');
          if (!pathname || pathname === '/') {
            rfc8414Uri = `${asUrlObj.protocol}//${asUrlObj.host}/.well-known/oauth-authorization-server`;
          } else {
            rfc8414Uri = `${asUrlObj.protocol}//${asUrlObj.host}/.well-known/oauth-authorization-server${pathname}`;
          }
          keycloakStyleUri = `${asUrl.replace(/[\/\\]+$/, '')}/.well-known/oauth-authorization-server`;
        } catch {
          rfc8414Uri = `${asUrl.replace(/[\/\\]+$/, '')}/.well-known/oauth-authorization-server`;
          keycloakStyleUri = rfc8414Uri;
        }

        this.addResult({
          id: 'as-2.1',
          category,
          requirement: 'AS metadata endpoint accessible',
          status: 'fail',
          message: `Could not retrieve AS metadata. Tried: (1) ${asUrl} directly, (2) RFC 8414 standard: ${rfc8414Uri}, (3) Appended to path: ${keycloakStyleUri}`,
          expected: 'AS metadata document with issuer field',
          actual: response ? `HTTP ${response.status}` : 'No valid response',
          details: {
            asUrl,
            attemptedUrls: [asUrl, rfc8414Uri, keycloakStyleUri],
            lastStatus: response?.status
          },
          rfcReference: 'RFC 8414 Section 3',
          rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-3',
          remediation: `Ensure AS metadata is available at one of these locations. RFC 8414 requires it at ${rfc8414Uri} (well-known URI inserted between host and path).`,
        });

        // Skip remaining AS tests
        ['as-2.2', 'as-2.3', 'as-2.4', 'as-2.5'].forEach((testId, index) => {
          const fields = ['registration_endpoint', 'authorization_endpoint', 'token_endpoint', 'scopes_supported'];
          const required = [false, true, true, false];
          this.addResult({
            id: testId,
            category,
            requirement: `AS metadata contains ${fields[index]}${required[index] ? ' (REQUIRED)' : ' (OPTIONAL/RECOMMENDED)'}`,
            status: 'skip',
            message: 'Skipped due to AS metadata discovery failure',
          });
        });
      }
    } catch (error) {
      this.addResult({
        id: 'as-2.1',
        category,
        requirement: 'AS metadata endpoint accessible',
        status: 'fail',
        message: `Discovery failed: ${error instanceof Error ? error.message : String(error)}`,
        expected: 'AS metadata document at well-known endpoint',
        actual: 'Network or fetch error',
        details: {
          asUrl,
          error: error instanceof Error ? error.message : String(error)
        },
      });

      // Skip remaining AS tests
      ['as-2.2', 'as-2.3', 'as-2.4', 'as-2.5'].forEach((testId, index) => {
        const fields = ['registration_endpoint', 'authorization_endpoint', 'token_endpoint', 'scopes_supported'];
        const required = [false, true, true, false];
        this.addResult({
          id: testId,
          category,
          requirement: `AS metadata contains ${fields[index]}${required[index] ? ' (REQUIRED)' : ' (OPTIONAL/RECOMMENDED)'}`,
          status: 'skip',
          message: 'Skipped due to AS metadata discovery failure',
        });
      });
    }
  }

  // ==================================================================
  // 3. Dynamic Client Registration (RFC 7591)
  // ==================================================================

  private async testDynamicClientRegistration() {
    const category = ComplianceCategory.DCR;
    const asMetadata = this.cache.get('asMetadata') as Record<string, unknown> | undefined;
    const registrationEndpoint = asMetadata?.registration_endpoint as string | undefined;

    // Skip DCR if using pre-configured client
    if (this.config.usePreConfiguredClient) {
      this.addResult({
        id: 'dcr-3.1',
        category,
        requirement: 'DCR tests',
        status: 'skip',
        message: 'Using pre-configured client_id - DCR not required',
      });
      return;
    }

    if (!registrationEndpoint) {
      this.addResult({
        id: 'dcr-3.1',
        category,
        requirement: 'Registration endpoint accepts POST',
        status: 'skip',
        message: 'No registration endpoint available from AS metadata',
      });
      return;
    }

    try {
      // Use configured callback port or default to 3000
      const callbackPort = this.config.callbackPort || 3000;
      const clientMetadata: Record<string, any> = {
        client_name: 'MCP Compliance Tester',
        redirect_uris: [`http://localhost:${callbackPort}/callback`],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      };

      // Only include scope if configured (some servers reject scope in DCR)
      if (this.config.scope) {
        clientMetadata.scope = this.config.scope;
      }

      const response = await this.fetchWithTimeout(registrationEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(clientMetadata),
      });

      // Test 3.1: Endpoint accepts POST
      this.addResult({
        id: 'dcr-3.1',
        category,
        requirement: 'Registration endpoint accepts POST',
        status: response.status !== 405 ? 'pass' : 'fail',
        message: response.status === 405 ? 'POST method not allowed' : undefined,
        details: { status: response.status },
      });

      // Test 3.2: Returns 201 on success (RFC 7591 requirement)
      if (response.ok) {
        this.addResult({
          id: 'dcr-3.2',
          category,
          requirement: 'Returns HTTP 201 on successful registration (REQUIRED)',
          status: response.status === 201 ? 'pass' : 'fail',
          message: response.status !== 201 ? `RFC 7591 requires 201, got ${response.status}` : undefined,
          details: { status: response.status },
        });

        const registrationResponse = await response.json();
        this.cache.set('clientRegistration', registrationResponse);

        // Test remaining registration response fields
        await this.testRegistrationResponseFields(category, registrationResponse);
      } else {
        // Registration failed - try to get error details
        let errorBody: any = null;
        try {
          errorBody = await response.json();
        } catch {
          // Response body might not be JSON
        }

        this.addResult({
          id: 'dcr-3.2',
          category,
          requirement: 'Returns HTTP 201 on successful registration (REQUIRED)',
          status: 'fail',
          message: `Registration failed with HTTP ${response.status}`,
          details: {
            status: response.status,
            requestBody: clientMetadata,
            errorResponse: errorBody
          },
        });

        // Fallback Test 3.2a: Try with refresh_token grant type
        // Some servers (like FastMCP) incorrectly require refresh_token despite RFC 7591 not mandating it
        const fallbackMetadata = {
          ...clientMetadata,
          grant_types: ['authorization_code', 'refresh_token'],
        };

        let fallbackResponse: Response | null = null;
        try {
          fallbackResponse = await this.fetchWithTimeout(registrationEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(fallbackMetadata),
          });

          if (fallbackResponse.ok) {
            // Fallback succeeded - server has non-compliant strict requirements
            this.addResult({
              id: 'dcr-3.2a',
              category,
              requirement: 'Accepts registration with refresh_token grant (FALLBACK)',
              status: 'warning',
              message: 'Registration succeeded when refresh_token was added to grant_types. This indicates server has stricter requirements than RFC 7591.',
              expected: 'Server should accept authorization_code alone per RFC 7591',
              actual: 'Server requires refresh_token in grant_types',
              details: {
                status: fallbackResponse.status,
                requestBody: fallbackMetadata
              },
              rfcReference: 'RFC 7591 Section 2',
              rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7591.html#section-2',
              remediation: 'RFC 7591 does not require refresh_token grant type for registration. Your server should accept clients registering with only authorization_code. Consider relaxing this validation or document this as a server-specific requirement.',
              indentLevel: 1,
            });

            // Process the successful fallback registration
            const registrationResponse = await fallbackResponse.json();
            this.cache.set('clientRegistration', registrationResponse);

            // Continue with remaining tests using the fallback registration
            await this.testRegistrationResponseFields(category, registrationResponse);
          } else {
            // Fallback also failed
            this.addResult({
              id: 'dcr-3.2a',
              category,
              requirement: 'Accepts registration with refresh_token grant (FALLBACK)',
              status: 'fail',
              message: `Fallback registration also failed with HTTP ${fallbackResponse.status}`,
              details: {
                status: fallbackResponse.status,
                requestBody: fallbackMetadata
              },
              indentLevel: 1,
            });

            // Skip remaining tests
            ['dcr-3.3', 'dcr-3.4', 'dcr-3.5'].forEach((testId, index) => {
              const requirements = [
                'Registration response contains client_id (REQUIRED)',
                'client_secret_expires_at present when client_secret issued (REQUIRED)',
                'Supports PKCE (token_endpoint_auth_method: none)'
              ];
              this.addResult({
                id: testId,
                category,
                requirement: requirements[index],
                status: 'skip',
                message: 'Skipped due to registration failure',
              });
            });
          }
        } catch (fallbackError) {
          this.addResult({
            id: 'dcr-3.2a',
            category,
            requirement: 'Accepts registration with refresh_token grant (FALLBACK)',
            status: 'fail',
            message: `Fallback test failed: ${fallbackError instanceof Error ? fallbackError.message : String(fallbackError)}`,
            indentLevel: 1,
          });

          // Skip remaining tests
          ['dcr-3.3', 'dcr-3.4', 'dcr-3.5'].forEach((testId, index) => {
            const requirements = [
              'Registration response contains client_id (REQUIRED)',
              'client_secret_expires_at present when client_secret issued (REQUIRED)',
              'Supports PKCE (token_endpoint_auth_method: none)'
            ];
            this.addResult({
              id: testId,
              category,
              requirement: requirements[index],
              status: 'skip',
              message: 'Skipped due to registration failure',
            });
          });
        }
      }
    } catch (error) {
      this.addResult({
        id: 'dcr-3.1',
        category,
        requirement: 'Registration endpoint accepts POST',
        status: 'fail',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Helper method to test registration response fields
  private async testRegistrationResponseFields(category: ComplianceCategory, registrationResponse: any) {
    // Test 3.3: Response contains client_id (REQUIRED per RFC 7591)
    const hasClientId = 'client_id' in registrationResponse;
    this.addResult({
      id: 'dcr-3.3',
      category,
      requirement: 'Registration response contains client_id (REQUIRED)',
      status: hasClientId ? 'pass' : 'fail',
      message: hasClientId ? undefined : 'client_id REQUIRED by RFC 7591 but missing from response',
      details: { client_id: registrationResponse.client_id },
    });

    // Test 3.4: Validates client_secret_expires_at if client_secret issued
    if ('client_secret' in registrationResponse) {
      const hasExpiresAt = 'client_secret_expires_at' in registrationResponse;
      this.addResult({
        id: 'dcr-3.4',
        category,
        requirement: 'client_secret_expires_at present when client_secret issued (REQUIRED)',
        status: hasExpiresAt ? 'pass' : 'fail',
        message: hasExpiresAt ? undefined : 'client_secret_expires_at REQUIRED when client_secret is issued',
        details: {
          client_secret_present: true,
          client_secret_expires_at: registrationResponse.client_secret_expires_at
        },
      });
    } else {
      this.addResult({
        id: 'dcr-3.4',
        category,
        requirement: 'client_secret_expires_at present when client_secret issued (REQUIRED)',
        status: 'skip',
        message: 'No client_secret issued (expected for public clients with PKCE)',
      });
    }

    // Test 3.5: Supports PKCE (token_endpoint_auth_method: none)
    const supportsPKCE = registrationResponse.token_endpoint_auth_method === 'none';
    this.addResult({
      id: 'dcr-3.5',
      category,
      requirement: 'Supports PKCE (token_endpoint_auth_method: none)',
      status: supportsPKCE ? 'pass' : 'skip',
      message: supportsPKCE ? undefined : `Got token_endpoint_auth_method: ${registrationResponse.token_endpoint_auth_method} (PKCE uses 'none')`,
      details: { token_endpoint_auth_method: registrationResponse.token_endpoint_auth_method },
    });
  }

  // ==================================================================
  // 4. OAuth 2.1 + PKCE Flow
  // ==================================================================

  private async testOAuthFlow() {
    const category = ComplianceCategory.OAUTH_FLOW;
    const asMetadata = this.cache.get('asMetadata') as Record<string, unknown> | undefined;

    if (!asMetadata) {
      this.addResult({
        id: 'oauth-4.1',
        category,
        requirement: 'Supports authorization_code grant type',
        status: 'skip',
        message: 'No AS metadata available',
      });
      return;
    }

    // Password flow removed - pre-configured client uses same authorization_code flow

    // Test 4.1: authorization_code grant supported
    // Per RFC 8414, grant_types_supported is OPTIONAL. Default is ["authorization_code", "implicit"]
    const grantTypes = asMetadata.grant_types_supported as string[] | undefined;
    const supportsAuthCode = !grantTypes || grantTypes.includes('authorization_code');
    this.addResult({
      id: 'oauth-4.1',
      category,
      requirement: 'Supports authorization_code grant type',
      status: supportsAuthCode ? 'pass' : 'fail',
      message: supportsAuthCode
        ? (grantTypes ? 'authorization_code in grant_types_supported' : 'grant_types_supported not specified (default includes authorization_code)')
        : 'authorization_code not in grant_types_supported',
      details: { grant_types_supported: grantTypes || 'not specified (defaults to authorization_code and implicit)' },
    });

    // Test 4.2: PKCE support (code_challenge_methods_supported)
    const codeChallengeMethods = asMetadata.code_challenge_methods_supported as string[] | undefined;
    const supportsPKCE = codeChallengeMethods?.includes('S256');
    this.addResult({
      id: 'oauth-4.2',
      category,
      requirement: 'Supports PKCE with S256 (code_challenge_methods_supported)',
      status: supportsPKCE ? 'pass' : (codeChallengeMethods ? 'fail' : 'skip'),
      message: supportsPKCE
        ? 'S256 in code_challenge_methods_supported'
        : (codeChallengeMethods ? 'S256 not in code_challenge_methods_supported' : 'code_challenge_methods_supported not advertised'),
      details: { code_challenge_methods_supported: codeChallengeMethods || 'not specified' },
    });

    // If interactive testing enabled, execute the full OAuth flow
    if (this.config.interactiveAuth) {
      await this.executeOAuthFlow(category, asMetadata);
    } else {
      // Skip interactive tests
      this.addResult({
        id: 'oauth-4.3',
        category,
        requirement: 'Supports resource parameter (RFC 8707)',
        status: 'skip',
        message: 'Requires full OAuth flow execution - enable interactiveAuth to test',
      });

      this.addResult({
        id: 'oauth-4.4',
        category,
        requirement: 'Token endpoint validates PKCE',
        status: 'skip',
        message: 'Requires full OAuth flow execution - enable interactiveAuth to test',
      });

      this.addResult({
        id: 'oauth-4.5',
        category,
        requirement: 'Issues Bearer access tokens',
        status: 'skip',
        message: 'Requires full OAuth flow execution - enable interactiveAuth to test',
      });

      this.addResult({
        id: 'oauth-4.6',
        category,
        requirement: 'Token response includes required fields',
        status: 'skip',
        message: 'Requires full OAuth flow execution - enable interactiveAuth to test',
      });
    }
  }


  /**
   * Execute the full OAuth 2.1 + PKCE authorization code flow
   * This requires user interaction via browser
   */
  private async executeOAuthFlow(category: ComplianceCategory, asMetadata: Record<string, unknown>) {
    const authorizationEndpoint = asMetadata.authorization_endpoint as string | undefined;
    const tokenEndpoint = asMetadata.token_endpoint as string | undefined;
    const clientRegistration = this.cache.get('clientRegistration') as Record<string, unknown> | undefined;

    if (!authorizationEndpoint || !tokenEndpoint) {
      this.addResult({
        id: 'oauth-4.3',
        category,
        requirement: 'Supports resource parameter (RFC 8707)',
        status: 'skip',
        message: 'Missing authorization or token endpoint in AS metadata',
      });
      return;
    }

    // Use pre-configured client or DCR-registered client
    let clientId: string;
    let redirectUri: string;

    if (this.config.usePreConfiguredClient && this.config.clientId) {
      clientId = this.config.clientId;
      // clientSecret available at this.config.clientSecret if needed for confidential clients
      const callbackPort = this.config.callbackPort || 3000;
      redirectUri = `http://localhost:${callbackPort}/callback`;
    } else if (clientRegistration && clientRegistration.client_id) {
      clientId = clientRegistration.client_id as string;
      // clientSecret available at clientRegistration.client_secret if needed
      redirectUri = (clientRegistration.redirect_uris as string[])?.[0] || 'http://localhost:3000/callback';
    } else {
      this.addResult({
        id: 'oauth-4.3',
        category,
        requirement: 'Supports resource parameter (RFC 8707)',
        status: 'skip',
        message: 'No client available - either DCR must succeed or provide pre-configured client_id',
      });
      return;
    }

    const callbackPort = this.config.callbackPort || 3000;

    // Generate PKCE parameters
    const pkce = generatePKCEParams();
    this.cache.set('pkce', pkce);

    console.log('\n🔐 Starting interactive OAuth flow...');
    console.log('You will be redirected to your browser to authenticate.');

    try {
      // Start callback server
      const callbackPromise = startCallbackServer(callbackPort);

      // Build authorization URL
      const authUrl = new URL(authorizationEndpoint);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', redirectUri);

      // Use configured scope, or scope from DCR registration (if any)
      // Don't default to openid - let the server decide if no scope specified
      const registeredScope = (clientRegistration?.scope as string) || undefined;
      const scopeToUse = this.config.scope || registeredScope;
      if (scopeToUse) {
        authUrl.searchParams.set('scope', scopeToUse);
      }

      authUrl.searchParams.set('state', pkce.state);
      authUrl.searchParams.set('code_challenge', pkce.codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      // Add resource parameter if configured (RFC 8707)
      if (this.config.resourceUri) {
        authUrl.searchParams.set('resource', this.config.resourceUri);
      }

      console.log(`\n📱 Opening browser to: ${authUrl.toString()}\n`);

      // Open browser - Windows needs empty title "" before URL
      const openCommand = process.platform === 'win32' ? 'start ""' :
                         process.platform === 'darwin' ? 'open' : 'xdg-open';
      exec(`${openCommand} "${authUrl.toString()}"`);

      // Wait for callback
      const callback = await callbackPromise;

      if (callback.error) {
        this.addResult({
          id: 'oauth-4.3',
          category,
          requirement: 'Authorization endpoint accepts requests',
          status: 'fail',
          message: `Authorization failed: ${callback.error}`,
          details: callback as unknown as Record<string, unknown>,
        });
        return;
      }

      if (!callback.code) {
        this.addResult({
          id: 'oauth-4.3',
          category,
          requirement: 'Authorization endpoint returns authorization code',
          status: 'fail',
          message: 'No authorization code received',
          details: callback as unknown as Record<string, unknown>,
        });
        return;
      }

      // Test 4.3: Verify state parameter (CSRF protection)
      const stateMatches = callback.state === pkce.state;
      this.addResult({
        id: 'oauth-4.3',
        category,
        requirement: 'Authorization endpoint returns matching state parameter (CSRF protection)',
        status: stateMatches ? 'pass' : 'fail',
        message: stateMatches ? 'State parameter matches' : 'State parameter mismatch',
        expected: pkce.state,
        actual: callback.state,
        details: { expected: pkce.state, received: callback.state },
        rfcReference: 'RFC 6749 Section 10.12',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12',
      });

      console.log('✅ Authorization code received');
      console.log('🔄 Exchanging code for tokens...\n');

      // Exchange authorization code for tokens
      await this.exchangeCodeForTokens(category, tokenEndpoint, {
        code: callback.code,
        clientId,
        redirectUri,
        codeVerifier: pkce.codeVerifier,
        resourceUri: this.config.resourceUri,
      });

    } catch (error) {
      this.addResult({
        id: 'oauth-4.3',
        category,
        requirement: 'OAuth flow execution',
        status: 'fail',
        message: `OAuth flow failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  /**
   * Exchange authorization code for access tokens
   */
  private async exchangeCodeForTokens(
    category: ComplianceCategory,
    tokenEndpoint: string,
    params: {
      code: string;
      clientId: string;
      redirectUri: string;
      codeVerifier: string;
      resourceUri?: string;
    }
  ) {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: params.code,
      client_id: params.clientId,
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
    });

    // Add resource parameter if specified (RFC 8707)
    if (params.resourceUri) {
      body.set('resource', params.resourceUri);
    }

    try {
      const response = await this.fetchWithTimeout(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });

      // Test 4.4: Token endpoint accepts request
      this.addResult({
        id: 'oauth-4.4',
        category,
        requirement: 'Token endpoint accepts authorization_code grant with PKCE',
        status: response.ok ? 'pass' : 'fail',
        message: response.ok ? undefined : `Token endpoint returned HTTP ${response.status}`,
        details: { status: response.status },
      });

      if (!response.ok) {
        const errorBody = await response.text();
        this.addResult({
          id: 'oauth-4.5',
          category,
          requirement: 'Token endpoint validates PKCE code_verifier',
          status: 'fail',
          message: `Token request failed with HTTP ${response.status}`,
          details: { status: response.status, error: errorBody },
        });
        return;
      }

      const tokenResponse = await response.json() as Record<string, any>;
      this.cache.set('tokenResponse', tokenResponse);

      // Test 4.5: Access token issued
      const hasAccessToken = 'access_token' in tokenResponse;
      this.addResult({
        id: 'oauth-4.5',
        category,
        requirement: 'Issues access_token (REQUIRED)',
        status: hasAccessToken ? 'pass' : 'fail',
        message: hasAccessToken ? undefined : 'access_token missing from token response',
        details: { has_access_token: hasAccessToken },
        rfcReference: 'RFC 6749 Section 5.1',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1',
      });

      // Test 4.6: Token type is Bearer
      const tokenType = tokenResponse.token_type;
      const isBearer = tokenType?.toLowerCase() === 'bearer';
      this.addResult({
        id: 'oauth-4.6',
        category,
        requirement: 'Issues Bearer token_type',
        status: isBearer ? 'pass' : 'fail',
        message: isBearer ? undefined : `token_type is "${tokenType}", expected "Bearer"`,
        expected: 'Bearer',
        actual: tokenType,
        details: { token_type: tokenType },
        rfcReference: 'RFC 6750 Section 1',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6750.html#section-1',
      });

      // Test 4.7: expires_in present
      const hasExpiresIn = 'expires_in' in tokenResponse;
      this.addResult({
        id: 'oauth-4.7',
        category,
        requirement: 'Token response includes expires_in (RECOMMENDED)',
        status: hasExpiresIn ? 'pass' : 'skip',
        message: hasExpiresIn ? `Token expires in ${tokenResponse.expires_in} seconds` : 'expires_in not present (RECOMMENDED but not required)',
        details: { expires_in: tokenResponse.expires_in },
        rfcReference: 'RFC 6749 Section 5.1',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1',
      });

      // Test 4.8: Refresh token issued (for authorization_code + refresh_token)
      const hasRefreshToken = 'refresh_token' in tokenResponse;
      this.addResult({
        id: 'oauth-4.8',
        category,
        requirement: 'Issues refresh_token (OPTIONAL)',
        status: hasRefreshToken ? 'pass' : 'skip',
        message: hasRefreshToken ? 'refresh_token issued' : 'refresh_token not issued (OPTIONAL)',
        details: { has_refresh_token: hasRefreshToken },
      });

      // Test 4.9: Resource parameter support (RFC 8707)
      if (params.resourceUri) {
        // Check if token response includes audience restriction
        const hasAudience = 'aud' in tokenResponse || 'audience' in tokenResponse;
        this.addResult({
          id: 'oauth-4.9',
          category,
          requirement: 'Supports resource parameter audience restriction (RFC 8707)',
          status: hasAudience ? 'pass' : 'skip',
          message: hasAudience ? 'Token includes audience restriction' : 'Cannot verify audience restriction without decoding token',
          details: {
            resource_requested: params.resourceUri,
            aud: tokenResponse.aud,
            audience: tokenResponse.audience,
          },
          rfcReference: 'RFC 8707',
          rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707.html',
        });
      }

      console.log('✅ Tokens received successfully\n');

      // Run JWT validation tests if we have an access token
      if (hasAccessToken) {
        await this.testJWTValidation();
      }

    } catch (error) {
      this.addResult({
        id: 'oauth-4.4',
        category,
        requirement: 'Token endpoint exchange',
        status: 'fail',
        message: `Token exchange failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  // ==================================================================
  // JWT Validation Tests (RFC 9068)
  // ==================================================================

  /**
   * Test JWT access token validation
   */
  private async testJWTValidation() {
    const category = ComplianceCategory.JWT_VALIDATION;
    const tokenResponse = this.cache.get('tokenResponse') as Record<string, any> | undefined;
    const asMetadata = this.cache.get('asMetadata') as Record<string, any> | undefined;

    if (!tokenResponse?.access_token) {
      this.addResult({
        id: 'jwt-5.0',
        category,
        requirement: 'JWT access token available for validation',
        status: 'skip',
        message: 'No access token available - OAuth flow must complete first',
      });
      return;
    }

    const accessToken = tokenResponse.access_token as string;

    // Test 5.1: Check if token is a JWT (has 3 base64url parts)
    const parts = accessToken.split('.');
    const isJWT = parts.length === 3;

    this.addResult({
      id: 'jwt-5.1',
      category,
      requirement: 'Access token is a JWT (three Base64URL-encoded parts)',
      status: isJWT ? 'pass' : 'warning',
      message: isJWT ? 'Access token is a valid JWT format' : 'Access token is not a JWT (may be opaque token)',
      details: { parts: parts.length, isJWT },
    });

    if (!isJWT) {
      this.addResult({
        id: 'jwt-5.2',
        category,
        requirement: 'JWT header validation',
        status: 'skip',
        message: 'Token is not a JWT - cannot validate structure',
      });
      return;
    }

    // Decode JWT parts (without verification first)
    let header: Record<string, any>;
    let payload: Record<string, any>;

    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    } catch (e) {
      this.addResult({
        id: 'jwt-5.2',
        category,
        requirement: 'JWT is properly Base64URL-encoded',
        status: 'fail',
        message: `Failed to decode JWT: ${e instanceof Error ? e.message : String(e)}`,
      });
      return;
    }

    this.addResult({
      id: 'jwt-5.2',
      category,
      requirement: 'JWT is properly Base64URL-encoded',
      status: 'pass',
      message: 'JWT header and payload successfully decoded',
      details: { header, payload_claims: Object.keys(payload) },
    });

    // Test 5.3: Header has required fields
    const hasAlg = 'alg' in header;
    const algIsValid = hasAlg && header.alg !== 'none';

    this.addResult({
      id: 'jwt-5.3',
      category,
      requirement: 'JWT header contains "alg" claim (not "none")',
      status: algIsValid ? 'pass' : 'fail',
      message: algIsValid ? `Algorithm: ${header.alg}` : 'Missing or invalid "alg" claim',
      expected: 'RS256, ES256, or similar',
      actual: header.alg,
      details: { alg: header.alg, typ: header.typ },
      rfcReference: 'RFC 7515 Section 4.1.1',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1',
    });

    // Test 5.4: Check for kid (key ID) in header (OPTIONAL but recommended)
    const hasKid = 'kid' in header;
    this.addResult({
      id: 'jwt-5.4',
      category,
      requirement: 'JWT header contains "kid" claim for key identification (OPTIONAL)',
      status: hasKid ? 'pass' : 'skip',
      message: hasKid ? `Key ID: ${header.kid}` : 'No "kid" claim (OPTIONAL) - key selection may be ambiguous',
      details: { kid: header.kid },
      rfcReference: 'RFC 7515 Section 4.1.4',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4',
    });

    // Test 5.5: Required claims present (iss, sub, aud, exp, iat)
    const requiredClaims = ['iss', 'sub', 'exp', 'iat'];
    const missingClaims = requiredClaims.filter(claim => !(claim in payload));

    this.addResult({
      id: 'jwt-5.5',
      category,
      requirement: 'JWT contains required claims (iss, sub, exp, iat)',
      status: missingClaims.length === 0 ? 'pass' : 'fail',
      message: missingClaims.length === 0
        ? 'All required claims present'
        : `Missing required claims: ${missingClaims.join(', ')}`,
      expected: 'iss, sub, exp, iat',
      actual: Object.keys(payload).join(', '),
      details: {
        present: requiredClaims.filter(c => c in payload),
        missing: missingClaims,
      },
      rfcReference: 'RFC 9068 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2',
    });

    // Test 5.6: Validate issuer matches AS metadata
    const expectedIssuer = asMetadata?.issuer;
    const tokenIssuer = payload.iss;
    const issuerMatches = expectedIssuer && tokenIssuer === expectedIssuer;

    this.addResult({
      id: 'jwt-5.6',
      category,
      requirement: 'JWT issuer (iss) matches authorization server',
      status: issuerMatches ? 'pass' : (expectedIssuer ? 'fail' : 'warning'),
      message: issuerMatches
        ? 'Issuer matches authorization server metadata'
        : (expectedIssuer ? 'Issuer mismatch' : 'Cannot verify issuer - no AS metadata available'),
      expected: expectedIssuer,
      actual: tokenIssuer,
      details: { expected_issuer: expectedIssuer, token_issuer: tokenIssuer },
      rfcReference: 'RFC 9068 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2',
    });

    // Test 5.7: Token not expired
    const now = Math.floor(Date.now() / 1000);
    const exp = payload.exp as number | undefined;
    const isExpired = exp !== undefined && exp < now;
    const expiresIn = exp ? exp - now : undefined;

    this.addResult({
      id: 'jwt-5.7',
      category,
      requirement: 'JWT is not expired (exp claim)',
      status: exp === undefined ? 'fail' : (isExpired ? 'fail' : 'pass'),
      message: exp === undefined
        ? 'No expiration claim (exp) in token'
        : (isExpired ? `Token expired ${Math.abs(expiresIn!)} seconds ago` : `Token valid for ${expiresIn} seconds`),
      details: { exp, now, expires_in_seconds: expiresIn },
      rfcReference: 'RFC 7519 Section 4.1.4',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4',
    });

    // Test 5.8: Token not used before issued (iat)
    const iat = payload.iat as number | undefined;
    const iatValid = iat === undefined || iat <= now + 60; // Allow 60s clock skew

    this.addResult({
      id: 'jwt-5.8',
      category,
      requirement: 'JWT issued-at (iat) is not in the future',
      status: iat === undefined ? 'warning' : (iatValid ? 'pass' : 'fail'),
      message: iat === undefined
        ? 'No issued-at claim (iat) in token'
        : (iatValid ? 'Token issued-at is valid' : 'Token appears to be issued in the future'),
      details: { iat, now, issued_seconds_ago: iat ? now - iat : undefined },
      rfcReference: 'RFC 7519 Section 4.1.6',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6',
    });

    // Test 5.9: JWKS endpoint available and reachable (OPTIONAL per RFC 8414)
    const jwksUri = asMetadata?.jwks_uri;

    if (!jwksUri) {
      this.addResult({
        id: 'jwt-5.9',
        category,
        requirement: 'JWKS URI available in AS metadata (OPTIONAL)',
        status: 'warning',
        message: 'No jwks_uri in authorization server metadata - signature verification not possible',
        rfcReference: 'RFC 8414 Section 2',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-2',
      });
      this.addResult({
        id: 'jwt-5.14',
        category,
        requirement: 'JWT signature is cryptographically valid',
        status: 'skip',
        message: 'Cannot verify signature - no JWKS URI available',
      });
    } else {
      // Try to fetch JWKS
      try {
        const jwksResponse = await this.fetchWithTimeout(jwksUri);

        this.addResult({
          id: 'jwt-5.9',
          category,
          requirement: 'JWKS URI is reachable',
          status: jwksResponse.ok ? 'pass' : 'fail',
          message: jwksResponse.ok
            ? `JWKS endpoint accessible at ${jwksUri}`
            : `JWKS endpoint returned HTTP ${jwksResponse.status}`,
          details: { jwks_uri: jwksUri, status: jwksResponse.status },
          rfcReference: 'RFC 7517',
          rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7517.html',
        });

        if (!jwksResponse.ok) {
          this.addResult({
            id: 'jwt-5.14',
            category,
            requirement: 'JWT signature is cryptographically valid',
            status: 'skip',
            message: `Cannot verify signature - JWKS endpoint returned HTTP ${jwksResponse.status}`,
          });
        }

        if (jwksResponse.ok) {
          const jwks = await jwksResponse.json() as { keys?: Array<Record<string, any>> };

          // Test 5.10: JWKS contains keys
          const hasKeys = Array.isArray(jwks.keys) && jwks.keys.length > 0;
          this.addResult({
            id: 'jwt-5.10',
            category,
            requirement: 'JWKS contains signing keys',
            status: hasKeys ? 'pass' : 'fail',
            message: hasKeys
              ? `JWKS contains ${jwks.keys!.length} key(s)`
              : 'JWKS has no keys',
            details: {
              key_count: jwks.keys?.length || 0,
              key_ids: jwks.keys?.map(k => k.kid).filter(Boolean),
            },
          });

          if (!hasKeys) {
            this.addResult({
              id: 'jwt-5.14',
              category,
              requirement: 'JWT signature is cryptographically valid',
              status: 'skip',
              message: 'Cannot verify signature - JWKS has no keys',
            });
          }

          // Test 5.11: Matching key found for token's kid
          if (hasKeys && hasKid) {
            const matchingKey = jwks.keys!.find(k => k.kid === header.kid);
            this.addResult({
              id: 'jwt-5.11',
              category,
              requirement: 'JWKS contains key matching token "kid"',
              status: matchingKey ? 'pass' : 'fail',
              message: matchingKey
                ? `Found matching key for kid "${header.kid}"`
                : `No key found matching kid "${header.kid}"`,
              expected: header.kid,
              actual: jwks.keys!.map(k => k.kid).join(', '),
              details: {
                token_kid: header.kid,
                available_kids: jwks.keys!.map(k => k.kid).filter(Boolean),
                matching_key_alg: matchingKey?.alg,
                matching_key_use: matchingKey?.use,
              },
            });

            if (!matchingKey) {
              this.addResult({
                id: 'jwt-5.14',
                category,
                requirement: 'JWT signature is cryptographically valid',
                status: 'skip',
                message: `Cannot verify signature - no key found matching kid "${header.kid}"`,
              });
            }

            // Test 5.12: Key algorithm matches token algorithm
            if (matchingKey) {
              const algMatches = !matchingKey.alg || matchingKey.alg === header.alg;
              this.addResult({
                id: 'jwt-5.12',
                category,
                requirement: 'Key algorithm matches token algorithm',
                status: algMatches ? 'pass' : 'fail',
                message: algMatches
                  ? `Algorithm ${header.alg} is compatible with key`
                  : `Algorithm mismatch: token uses ${header.alg}, key specifies ${matchingKey.alg}`,
                expected: header.alg,
                actual: matchingKey.alg || '(not specified)',
                details: { token_alg: header.alg, key_alg: matchingKey.alg },
              });

              // Test 5.14: Cryptographic signature verification
              await this.verifyJWTSignature(category, accessToken, jwksUri, header, matchingKey);
            }
          } else if (hasKeys && !hasKid) {
            this.addResult({
              id: 'jwt-5.11',
              category,
              requirement: 'JWKS contains key matching token "kid"',
              status: 'skip',
              message: 'Token has no "kid" claim (OPTIONAL) - will attempt verification with available keys',
              details: { available_kids: jwks.keys!.map(k => k.kid).filter(Boolean) },
            });

            // Still attempt signature verification - jose will try available keys
            await this.verifyJWTSignature(category, accessToken, jwksUri, header, jwks.keys![0]);
          }
        }
      } catch (error) {
        this.addResult({
          id: 'jwt-5.9',
          category,
          requirement: 'JWKS URI is reachable',
          status: 'fail',
          message: `Failed to fetch JWKS: ${error instanceof Error ? error.message : String(error)}`,
          details: { jwks_uri: jwksUri },
        });
        this.addResult({
          id: 'jwt-5.14',
          category,
          requirement: 'JWT signature is cryptographically valid',
          status: 'skip',
          message: 'Cannot verify signature - failed to fetch JWKS',
        });
      }
    }

    // Test 5.13: Check for audience claim (OPTIONAL per RFC 7519, REQUIRED per RFC 9068)
    const aud = payload.aud;
    this.addResult({
      id: 'jwt-5.13',
      category,
      requirement: 'JWT contains audience (aud) claim (RECOMMENDED)',
      status: aud ? 'pass' : 'skip',
      message: aud
        ? `Audience: ${Array.isArray(aud) ? aud.join(', ') : aud}`
        : 'No audience claim (OPTIONAL) - token may be usable at any resource server',
      details: { aud },
      rfcReference: 'RFC 9068 Section 2.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2',
    });

    console.log('✅ JWT validation tests completed\n');
  }

  /**
   * Verify JWT signature cryptographically using jose library
   */
  private async verifyJWTSignature(
    category: ComplianceCategory,
    token: string,
    jwksUri: string,
    header: Record<string, any>,
    _matchingKey: Record<string, any>
  ) {
    try {
      // Create JWKS from the URI
      const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));

      // Verify the JWT signature
      const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS, {
        // Don't validate claims here - we already did that
        // Just verify the signature
      });

      this.addResult({
        id: 'jwt-5.14',
        category,
        requirement: 'JWT signature is cryptographically valid',
        status: 'pass',
        message: `Signature verified successfully using ${protectedHeader.alg} algorithm`,
        details: {
          algorithm: protectedHeader.alg,
          kid: protectedHeader.kid,
          verified_claims: Object.keys(payload),
        },
        rfcReference: 'RFC 7515 Section 5.2',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7515.html#section-5.2',
      });

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Check for specific error types
      let status: 'fail' | 'warning' = 'fail';
      let message = `Signature verification failed: ${errorMessage}`;

      if (errorMessage.includes('expired')) {
        // Token expired is not a signature failure
        status = 'warning';
        message = 'Token expired during verification (signature may still be valid)';
      } else if (errorMessage.includes('JWK')) {
        message = `Could not use key for verification: ${errorMessage}`;
      }

      this.addResult({
        id: 'jwt-5.14',
        category,
        requirement: 'JWT signature is cryptographically valid',
        status,
        message,
        details: {
          error: errorMessage,
          algorithm: header.alg,
          kid: header.kid,
          jwks_uri: jwksUri,
        },
        rfcReference: 'RFC 7515 Section 5.2',
        rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7515.html#section-5.2',
      });
    }
  }

  // ==================================================================
  // Helper Methods
  // ==================================================================

  private async fetchWithTimeout(url: string, options?: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      return response;
    } finally {
      clearTimeout(timeout);
    }
  }
}
