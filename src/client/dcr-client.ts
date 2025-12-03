import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import {
  ClientMetadata,
  RegistrationRequest,
  RegistrationResponse,
  RegistrationResponseSchema,
  ErrorResponseSchema
} from '../types/dcr.js';
import { DiscoveryClient } from './discovery.js';
import { ProtocolVersion } from '../types/protocol-version.js';
import { ClientIDMetadataHandler } from './client-id-metadata-handler.js';
import { AuthorizationServerMetadata } from '../types/oauth-discovery.js';

export type TransportType = 'stdio' | 'http';

export interface DCRClientConfig {
  // Transport type
  transportType: TransportType;

  // For stdio transport (local server)
  serverCommand?: string;
  serverArgs?: string[];

  // For HTTP transport (remote server)
  serverUrl?: string;

  // Initial access token for registration
  initialAccessToken?: string;

  // Protocol version (NEW)
  protocolVersion?: ProtocolVersion;
}

export class DCRClient {
  private client?: Client;
  private config: DCRClientConfig;
  private transport?: Transport;
  private authorizationServer?: string;
  private discoveryClient?: DiscoveryClient;
  private discoveredRegistrationEndpoint?: string;
  private discoveredAuthorizationEndpoint?: string;
  private discoveredTokenEndpoint?: string;
  private protocolVersion: ProtocolVersion;
  private clientIDMetadataHandler?: ClientIDMetadataHandler;
  private authServerMetadata?: AuthorizationServerMetadata;

  constructor(config: DCRClientConfig) {
    this.config = config;
    this.protocolVersion = config.protocolVersion || ProtocolVersion.PRE_2025_11_25;

    // Initialize Client ID Metadata handler for MCP 2025-11-25
    if (this.protocolVersion === ProtocolVersion.MCP_2025_11_25) {
      this.clientIDMetadataHandler = new ClientIDMetadataHandler();
    }

    // Only create MCP client for stdio transport
    if (config.transportType === 'stdio') {
      this.client = new Client(
        {
          name: 'dcr-test-client',
          version: '0.1.0'
        },
        {
          capabilities: {}
        }
      );
    }
  }

  /**
   * Connect to the MCP server and discover OAuth endpoints
   */
  async connect(): Promise<void> {
    // Step 1: For HTTP transport, serverUrl IS the authorization server
    // (already discovered by compliance-tester.ts)
    if (this.config.transportType === 'http' && this.config.serverUrl) {
      console.log('Using authorization server:', this.config.serverUrl);
      this.authorizationServer = this.config.serverUrl;

      // Initialize OAuth discovery client with the authorization server
      this.discoveryClient = new DiscoveryClient(this.authorizationServer);
    }

    // Step 2: Perform OAuth Discovery to get registration endpoint (RFC 8414)
    if (this.discoveryClient) {
      console.log('\nDiscovering OAuth endpoints from authorization server (RFC 8414)...');
      try {
        const endpoints = await this.discoveryClient.getEndpoints();
        console.log('Discovered endpoints:', endpoints);

        // Store full metadata for protocol version checks
        this.authServerMetadata = await this.discoveryClient.getMetadata();

        if (endpoints.registration) {
          this.discoveredRegistrationEndpoint = endpoints.registration;
          console.log('Registration endpoint:', endpoints.registration);
        } else {
          console.warn('Warning: No registration_endpoint found in OAuth discovery metadata');
        }

        if (endpoints.authorization) {
          this.discoveredAuthorizationEndpoint = endpoints.authorization;
        }

        if (endpoints.token) {
          this.discoveredTokenEndpoint = endpoints.token;
        }

        // Check protocol-specific features (MCP 2025-11-25)
        if (this.protocolVersion === ProtocolVersion.MCP_2025_11_25) {
          this.validateMCP2025Support();
        }
      } catch (error) {
        console.warn(
          `OAuth Discovery failed: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }

    // Step 3: MCP connection is OPTIONAL
    // DCR is a separate OAuth operation and doesn't require MCP connection
    // Only connect to MCP if using stdio transport
    if (this.config.transportType === 'stdio') {
      if (!this.config.serverCommand) {
        throw new Error('serverCommand is required for stdio transport');
      }

      if (!this.client) {
        throw new Error('MCP Client not initialized for stdio transport');
      }

      console.log('\nConnecting to MCP server via stdio...');
      this.transport = new StdioClientTransport({
        command: this.config.serverCommand,
        args: this.config.serverArgs || []
      });

      await this.client.connect(this.transport);
      console.log('Connected to MCP server');
    }
    // For HTTP transport, we don't need to connect to MCP server
    // DCR happens via direct HTTP calls to the OAuth endpoints
  }

  /**
   * Get the registration endpoint (from discovery)
   */
  getRegistrationEndpoint(): string {
    if (this.discoveredRegistrationEndpoint) {
      return this.discoveredRegistrationEndpoint;
    }

    throw new Error(
      'No registration endpoint discovered. Ensure the MCP server provides OAuth 2.0 Protected Resource Metadata (RFC 9728).'
    );
  }

  /**
   * Get the authorization endpoint (from discovery)
   */
  getAuthorizationEndpoint(): string {
    if (this.discoveredAuthorizationEndpoint) {
      return this.discoveredAuthorizationEndpoint;
    }
    // Fallback to constructing it if not discovered (though RFC 8414 says it should be there)
    if (this.authorizationServer) {
      return `${this.authorizationServer.replace(/\/$/, '')}/authorize`;
    }
    throw new Error('No authorization endpoint discovered');
  }

  /**
   * Get the token endpoint (from discovery)
   */
  getTokenEndpoint(): string {
    if (this.discoveredTokenEndpoint) {
      return this.discoveredTokenEndpoint;
    }
    // Fallback
    if (this.authorizationServer) {
      return `${this.authorizationServer.replace(/\/$/, '')}/token`;
    }
    throw new Error('No token endpoint discovered');
  }

  /**
   * Get the discovered authorization server
   */
  getAuthorizationServer(): string | undefined {
    return this.authorizationServer;
  }

  /**
   * Disconnect from the MCP server
   */
  async disconnect(): Promise<void> {
    if (this.config.transportType === 'stdio' && this.client) {
      await this.client.close();
    }
    // For HTTP, no persistent connection to close
  }

  /**
   * Register a client with the DCR endpoint
   * Implements RFC 7591 Section 3.1
   *
   * This is a direct HTTP POST to the OAuth registration endpoint,
   * NOT an MCP tool call.
   */
  async registerClient(metadata: ClientMetadata): Promise<RegistrationResponse> {
    const registrationEndpoint = this.getRegistrationEndpoint();

    const request: RegistrationRequest = {
      ...metadata
    };

    // Remove token from request body - it goes in the header
    delete (request as any).token;

    let response: Response | undefined;
    let responseBody: any;

    try {
      // RFC 7591: POST to registration endpoint with optional initial access token in Authorization header
      response = await fetch(registrationEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(this.config.initialAccessToken && {
            Authorization: `Bearer ${this.config.initialAccessToken}`
          })
        },
        body: JSON.stringify(request)
      });

      if (!response.ok) {
        // Read response body once (can't clone after reading)
        let errorBody: any;
        const responseText = await response.text();

        try {
          errorBody = JSON.parse(responseText);
        } catch {
          errorBody = responseText;
        }

        // Try to parse as RFC 7591 error response
        try {
          const errorResponse = ErrorResponseSchema.parse(errorBody);
          const dcrError = new DCRError(errorResponse.error, errorResponse.error_description);
          // Attach debug info
          (dcrError as any).debugInfo = {
            request: {
              method: 'POST',
              url: registrationEndpoint,
              headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
                Authorization: this.config.initialAccessToken ? 'Bearer ***' : undefined
              },
              body: request
            },
            response: {
              status: response.status,
              statusText: response.statusText,
              headers: Object.fromEntries(response.headers.entries()),
              body: errorBody
            }
          };
          throw dcrError;
        } catch (parseError) {
          const error = new Error(
            `Registration failed: ${response.status} ${response.statusText}`
          );
          (error as any).debugInfo = {
            request: {
              method: 'POST',
              url: registrationEndpoint,
              headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
                Authorization: this.config.initialAccessToken ? 'Bearer ***' : undefined
              },
              body: request
            },
            response: {
              status: response.status,
              statusText: response.statusText,
              headers: Object.fromEntries(response.headers.entries()),
              body: errorBody
            }
          };
          throw error;
        }
      }

      responseBody = await response.json();

      // Validate response against RFC 7591
      const validatedResponse = RegistrationResponseSchema.parse(responseBody);

      return validatedResponse;
    } catch (error) {
      if (error instanceof DCRError) {
        throw error;
      }

      // Enhance validation errors with debug info
      if (error instanceof Error && error.name === 'ZodError') {
        const enhancedError = new Error(`Validation failed: ${error.message}`);
        (enhancedError as any).validationErrors = error;
        (enhancedError as any).debugInfo = {
          request: {
            method: 'POST',
            url: registrationEndpoint,
            headers: {
              'Content-Type': 'application/json',
              Accept: 'application/json',
              Authorization: this.config.initialAccessToken ? 'Bearer ***' : undefined
            },
            body: request
          },
          response: response
            ? {
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries(response.headers.entries()),
                body: responseBody
              }
            : undefined
        };
        throw enhancedError;
      }

      throw error;
    }
  }

  /**
   * Read a client registration
   * Implements RFC 7592 Section 2
   *
   * This is a direct HTTP GET to the registration client URI,
   * NOT an MCP tool call.
   */
  async readClient(
    registrationClientUri: string,
    accessToken: string
  ): Promise<RegistrationResponse> {
    const response = await fetch(registrationClientUri, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Read client failed: ${response.status} ${response.statusText}`);
    }

    const responseBody = await response.json();
    return RegistrationResponseSchema.parse(responseBody);
  }

  /**
   * Update a client registration
   * Implements RFC 7592 Section 3
   *
   * This is a direct HTTP PUT to the registration client URI,
   * NOT an MCP tool call.
   */
  async updateClient(
    registrationClientUri: string,
    accessToken: string,
    metadata: ClientMetadata
  ): Promise<RegistrationResponse> {
    const response = await fetch(registrationClientUri, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: JSON.stringify(metadata)
    });

    if (!response.ok) {
      throw new Error(`Update client failed: ${response.status} ${response.statusText}`);
    }

    const responseBody = await response.json();
    return RegistrationResponseSchema.parse(responseBody);
  }

  /**
   * Delete a client registration
   * Implements RFC 7592 Section 4
   *
   * This is a direct HTTP DELETE to the registration client URI,
   * NOT an MCP tool call.
   */
  async deleteClient(registrationClientUri: string, accessToken: string): Promise<void> {
    const response = await fetch(registrationClientUri, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    if (!response.ok && response.status !== 204) {
      throw new Error(`Delete client failed: ${response.status} ${response.statusText}`);
    }
  }

  /**
   * Get server info
   */
  async getServerInfo(): Promise<{
    name: string;
    version: string;
    url?: string;
    authorizationServer?: string;
    protocolVersion?: ProtocolVersion;
  }> {
    if (this.config.transportType === 'stdio') {
      if (!this.client) {
        throw new Error('MCP Client not initialized');
      }
      const serverVersion = await this.client.getServerVersion();
      return {
        name: serverVersion?.name || 'MCP Server',
        version: serverVersion?.version || 'unknown',
        protocolVersion: this.protocolVersion
      };
    } else if (this.config.transportType === 'http') {
      // Return basic info for HTTP transport
      return {
        name: 'Remote MCP Server',
        version: 'unknown',
        url: this.config.serverUrl,
        authorizationServer: this.authorizationServer,
        protocolVersion: this.protocolVersion
      };
    }

    throw new Error('Invalid transport type');
  }

  /**
   * Get protocol version
   */
  getProtocolVersion(): ProtocolVersion {
    return this.protocolVersion;
  }

  /**
   * Get authorization server metadata
   */
  getAuthServerMetadata(): AuthorizationServerMetadata | undefined {
    return this.authServerMetadata;
  }

  /**
   * Get Client ID Metadata handler (MCP 2025-11-25 only)
   */
  getClientIDMetadataHandler(): ClientIDMetadataHandler | undefined {
    return this.clientIDMetadataHandler;
  }

  /**
   * Validate MCP 2025-11-25 support in authorization server
   * @private
   */
  private validateMCP2025Support(): void {
    if (!this.authServerMetadata) {
      console.warn('Cannot validate MCP 2025-11-25 support: metadata not available');
      return;
    }

    const warnings: string[] = [];

    // Check S256 PKCE support
    const pkceMethods = this.authServerMetadata.code_challenge_methods_supported || [];
    if (!pkceMethods.includes('S256')) {
      warnings.push('S256 PKCE is required for MCP 2025-11-25 but not advertised');
    }

    // Check Client ID Metadata Document support
    if (!this.authServerMetadata.client_id_metadata_document_supported) {
      warnings.push(
        'client_id_metadata_document_supported is not advertised. ' +
        'Client ID Metadata Documents may not be supported.'
      );
    }

    // Log warnings
    if (warnings.length > 0) {
      console.warn('\n⚠️  MCP 2025-11-25 Compatibility Warnings:');
      warnings.forEach(w => console.warn(`  - ${w}`));
    }
  }
}

export class DCRError extends Error {
  constructor(
    public code: string,
    public description?: string
  ) {
    super(description || code);
    this.name = 'DCRError';
  }
}
