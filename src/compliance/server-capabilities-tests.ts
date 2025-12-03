/**
 * MCP Server Capabilities Discovery Tests
 *
 * Tests authenticated access to MCP server and discovery of available:
 * - Tools (callable functions)
 * - Resources (data sources)
 * - Prompts (predefined templates)
 *
 * @see https://spec.modelcontextprotocol.io/specification/2025-11-25/server/capabilities/
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamablehttp.js';
import { ComplianceCategory, ComplianceTestResult } from '../types/compliance.js';

export interface ServerCapabilitiesTestConfig {
  serverUrl: string;
  accessToken: string;
  enableDebug?: boolean;
  allowHttpMcpConnection?: boolean;
}

/**
 * Run MCP Server Capabilities Discovery tests
 */
export async function runServerCapabilitiesTests(
  config: ServerCapabilitiesTestConfig
): Promise<ComplianceTestResult[]> {
  const results: ComplianceTestResult[] = [];
  const category = ComplianceCategory.SERVER_CAPABILITIES;

  let client: Client | null = null;

  try {
    // Test 10.1: Initialize MCP client with access token
    results.push({
      id: 'cap-10.1',
      category,
      requirement: 'Initialize authenticated MCP client connection',
      status: 'info',
      message: 'Attempting to connect to MCP server with OAuth access token',
      timestamp: new Date()
    });

    try {
      // Parse server URL to determine transport
      const url = new URL(config.serverUrl);

      if (url.protocol === 'http:' || url.protocol === 'https:') {
        // Check if HTTP is allowed for non-localhost URLs
        const isLocalhost = url.hostname === 'localhost' ||
                           url.hostname === '127.0.0.1' ||
                           url.hostname === '::1';

        if (url.protocol === 'http:' && !isLocalhost && !config.allowHttpMcpConnection) {
          results.push({
            id: 'cap-10.1',
            category,
            requirement: 'Initialize authenticated MCP client connection',
            status: 'skip',
            message: 'HTTP MCP connections to non-localhost servers disabled. Enable "Allow HTTP MCP Connection" option to test.',
            timestamp: new Date()
          });
          return results;
        }

        // Determine the correct MCP endpoint URL
        // MCP servers expose the protocol at /mcp endpoint
        let mcpUrl = url.href;
        if (!mcpUrl.includes('/mcp')) {
          // Try appending /mcp if not already in the path
          const pathEndsWithSlash = mcpUrl.endsWith('/');
          mcpUrl = pathEndsWithSlash ? `${mcpUrl}mcp` : `${mcpUrl}/mcp`;
        }

        console.log(`\n🔍 [MCP Client] Constructing MCP endpoint`);
        console.log(`   Original URL: ${url.href}`);
        console.log(`   MCP URL: ${mcpUrl}`);

        // Use StreamableHTTP transport for HTTP/HTTPS
        // Pass access token in Authorization header via requestInit
        const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
          requestInit: {
            headers: {
              'Authorization': `Bearer ${config.accessToken}`,
              'Accept': 'text/event-stream, application/json',
              'Content-Type': 'application/json'
            }
          }
        });

        client = new Client({
          name: 'mcp-oauth-compliance-tester',
          version: '1.0.0'
        }, {
          capabilities: {}
        });

        console.log('\n🔍 [MCP Client] Attempting to connect to server with access token');
        console.log(`   MCP Endpoint: ${mcpUrl}`);
        console.log(`   Transport: StreamableHTTP`);
        console.log(`   Authorization: Bearer ${config.accessToken.substring(0, 30)}...`);
        console.log(`   Access Token Length: ${config.accessToken.length}`);

        try {
          await client.connect(transport);
          console.log('✅ [MCP Client] Connected successfully\n');
        } catch (connectError) {
          console.error('❌ [MCP Client] Connection failed:', connectError);
          console.error('   Error details:', {
            message: connectError instanceof Error ? connectError.message : String(connectError),
            stack: connectError instanceof Error ? connectError.stack : undefined
          });
          throw connectError;
        }

        results.push({
          id: 'cap-10.1',
          category,
          requirement: 'Initialize authenticated MCP client connection',
          status: 'pass',
          message: `Successfully connected to MCP server via ${url.protocol.replace(':', '').toUpperCase()} with OAuth access token`,
          details: {
            server_url: config.serverUrl,
            mcp_endpoint: mcpUrl,
            transport: 'StreamableHTTP',
            protocol: url.protocol,
            access_token_prefix: config.accessToken.substring(0, 20) + '...',
            access_token_length: config.accessToken.length,
            headers_sent: {
              Authorization: 'Bearer ***',
              Accept: 'text/event-stream, application/json',
              'Content-Type': 'application/json'
            }
          },
          timestamp: new Date()
        });
      } else {
        // Unsupported protocol
        results.push({
          id: 'cap-10.1',
          category,
          requirement: 'Initialize authenticated MCP client connection',
          status: 'skip',
          message: `Unsupported protocol: ${url.protocol}. Only HTTP/HTTPS supported.`,
          timestamp: new Date()
        });
        return results;
      }
    } catch (error) {
      results.push({
        id: 'cap-10.1',
        category,
        requirement: 'Initialize authenticated MCP client connection',
        status: 'fail',
        message: `Failed to initialize MCP client: ${error instanceof Error ? error.message : String(error)}`,
        timestamp: new Date()
      });
      return results;
    }

    // Test 10.2: List available tools
    results.push({
      id: 'cap-10.2',
      category,
      requirement: 'List available tools',
      status: 'info',
      message: 'Querying server for available tools',
      timestamp: new Date()
    });

    try {
      const toolsResponse = await client!.listTools();
      const tools = toolsResponse.tools || [];

      const details: any = {
        tool_count: tools.length,
        tools: tools.map(t => ({
          name: t.name,
          description: t.description,
          input_schema: t.inputSchema
        }))
      };

      if (config.enableDebug) {
        details.debug = {
          request: {
            method: 'tools/list',
            jsonrpc: '2.0'
          },
          response: {
            tools: toolsResponse.tools
          }
        };
      }

      results.push({
        id: 'cap-10.2',
        category,
        requirement: 'List available tools',
        status: tools.length > 0 ? 'pass' : 'info',
        message: tools.length > 0
          ? `Server provides ${tools.length} tool(s): ${tools.map(t => t.name).join(', ')}`
          : 'Server provides no tools',
        details,
        timestamp: new Date()
      });
    } catch (error) {
      const errorDetails: any = {
        error_message: error instanceof Error ? error.message : String(error)
      };

      if (config.enableDebug) {
        errorDetails.debug = {
          request: {
            method: 'tools/list',
            jsonrpc: '2.0'
          },
          error: {
            message: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined
          }
        };
      }

      results.push({
        id: 'cap-10.2',
        category,
        requirement: 'List available tools',
        status: 'fail',
        message: `Failed to list tools: ${error instanceof Error ? error.message : String(error)}`,
        details: errorDetails,
        timestamp: new Date()
      });
    }

    // Test 10.3: List available resources
    results.push({
      id: 'cap-10.3',
      category,
      requirement: 'List available resources',
      status: 'info',
      message: 'Querying server for available resources',
      timestamp: new Date()
    });

    try {
      const resourcesResponse = await client!.listResources();
      const resources = resourcesResponse.resources || [];

      const details: any = {
        resource_count: resources.length,
        resources: resources.map(r => ({
          name: r.name,
          description: r.description,
          uri: r.uri,
          mime_type: r.mimeType
        }))
      };

      if (config.enableDebug) {
        details.debug = {
          request: {
            method: 'resources/list',
            jsonrpc: '2.0'
          },
          response: {
            resources: resourcesResponse.resources
          }
        };
      }

      results.push({
        id: 'cap-10.3',
        category,
        requirement: 'List available resources',
        status: resources.length > 0 ? 'pass' : 'info',
        message: resources.length > 0
          ? `Server provides ${resources.length} resource(s): ${resources.map(r => r.name).join(', ')}`
          : 'Server provides no resources',
        details,
        timestamp: new Date()
      });
    } catch (error) {
      const errorDetails: any = {
        error_message: error instanceof Error ? error.message : String(error)
      };

      if (config.enableDebug) {
        errorDetails.debug = {
          request: {
            method: 'resources/list',
            jsonrpc: '2.0'
          },
          error: {
            message: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined
          }
        };
      }

      results.push({
        id: 'cap-10.3',
        category,
        requirement: 'List available resources',
        status: 'fail',
        message: `Failed to list resources: ${error instanceof Error ? error.message : String(error)}`,
        details: errorDetails,
        timestamp: new Date()
      });
    }

    // Test 10.4: List available prompts
    results.push({
      id: 'cap-10.4',
      category,
      requirement: 'List available prompts',
      status: 'info',
      message: 'Querying server for available prompts',
      timestamp: new Date()
    });

    try {
      const promptsResponse = await client!.listPrompts();
      const prompts = promptsResponse.prompts || [];

      const details: any = {
        prompt_count: prompts.length,
        prompts: prompts.map(p => ({
          name: p.name,
          description: p.description,
          arguments: p.arguments
        }))
      };

      if (config.enableDebug) {
        details.debug = {
          request: {
            method: 'prompts/list',
            jsonrpc: '2.0'
          },
          response: {
            prompts: promptsResponse.prompts
          }
        };
      }

      results.push({
        id: 'cap-10.4',
        category,
        requirement: 'List available prompts',
        status: prompts.length > 0 ? 'pass' : 'info',
        message: prompts.length > 0
          ? `Server provides ${prompts.length} prompt(s): ${prompts.map(p => p.name).join(', ')}`
          : 'Server provides no prompts',
        details,
        timestamp: new Date()
      });
    } catch (error) {
      const errorDetails: any = {
        error_message: error instanceof Error ? error.message : String(error)
      };

      if (config.enableDebug) {
        errorDetails.debug = {
          request: {
            method: 'prompts/list',
            jsonrpc: '2.0'
          },
          error: {
            message: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined
          }
        };
      }

      results.push({
        id: 'cap-10.4',
        category,
        requirement: 'List available prompts',
        status: 'fail',
        message: `Failed to list prompts: ${error instanceof Error ? error.message : String(error)}`,
        details: errorDetails,
        timestamp: new Date()
      });
    }

    return results;
  } catch (error) {
    results.push({
      id: 'cap-10.0',
      category,
      requirement: 'Server capabilities discovery',
      status: 'fail',
      message: `Unexpected error: ${error instanceof Error ? error.message : String(error)}`,
      timestamp: new Date()
    });
    return results;
  } finally {
    // Clean up client connection
    if (client) {
      try {
        await client.close();
      } catch {
        // Ignore cleanup errors
      }
    }
  }
}
