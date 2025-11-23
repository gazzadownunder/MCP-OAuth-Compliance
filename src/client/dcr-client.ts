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
import { ProtectedResourceDiscoveryClient } from './protected-resource-discovery.js';

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

  constructor(config: DCRClientConfig) {
    this.config = config;

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
    // Step 1: Discover Authorization Server from MCP server (RFC 9728)
    if (this.config.transportType === 'http' && this.config.serverUrl) {
      console.log('Discovering authorization server from MCP server (RFC 9728)...');
      try {
        const protectedResourceClient = new ProtectedResourceDiscoveryClient(this.config.serverUrl);
        this.authorizationServer = await protectedResourceClient.getAuthorizationServer();
        console.log('Discovered authorization server:', this.authorizationServer);

        // Initialize OAuth discovery client with discovered issuer
        this.discoveryClient = new DiscoveryClient(this.authorizationServer);
      } catch (error) {
        console.warn(
          `Protected Resource Metadata discovery failed: ${error instanceof Error ? error.message : String(error)}`
        );
        console.warn('Unable to discover authorization server from MCP server');
      }
    }

    // Step 2: Perform OAuth Discovery to get registration endpoint (RFC 8414)
    if (this.discoveryClient) {
      console.log('\nDiscovering OAuth endpoints from authorization server (RFC 8414)...');
      try {
        const endpoints = await this.discoveryClient.getEndpoints();
        console.log('Discovered endpoints:', endpoints);

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

    try {
      // RFC 7591: POST to registration endpoint with optional initial access token in Authorization header
      const response = await fetch(registrationEndpoint, {
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
        // Try to parse as RFC 7591 error response
        try {
          const errorBody = await response.json();
          const errorResponse = ErrorResponseSchema.parse(errorBody);
          throw new DCRError(errorResponse.error, errorResponse.error_description);
        } catch (parseError) {
          throw new Error(`Registration failed: ${response.status} ${response.statusText}`);
        }
      }

      const responseBody = await response.json();

      // Validate response against RFC 7591
      const validatedResponse = RegistrationResponseSchema.parse(responseBody);

      return validatedResponse;
    } catch (error) {
      if (error instanceof DCRError) {
        throw error;
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
  }> {
    if (this.config.transportType === 'stdio') {
      if (!this.client) {
        throw new Error('MCP Client not initialized');
      }
      const serverVersion = await this.client.getServerVersion();
      return {
        name: serverVersion?.name || 'MCP Server',
        version: serverVersion?.version || 'unknown'
      };
    } else if (this.config.transportType === 'http') {
      // Return basic info for HTTP transport
      return {
        name: 'Remote MCP Server',
        version: 'unknown',
        url: this.config.serverUrl,
        authorizationServer: this.authorizationServer
      };
    }

    throw new Error('Invalid transport type');
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
