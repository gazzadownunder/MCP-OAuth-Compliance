import {
  ProtectedResourceMetadata,
  ProtectedResourceMetadataSchema,
  parseWWWAuthenticateHeader
} from '../types/protected-resource-metadata.js';
import { fetchWithDebug } from '../utils/fetch-with-debug.js';

/**
 * OAuth 2.0 Protected Resource Metadata Discovery Client
 * Implements RFC 9728 for MCP servers
 */
export class ProtectedResourceDiscoveryClient {
  private serverUrl: string;

  constructor(serverUrl: string) {
    this.serverUrl = serverUrl;
  }

  /**
   * Discover protected resource metadata from MCP server
   * Implements RFC 9728 Section 3
   */
  async discover(): Promise<ProtectedResourceMetadata> {
    // Step 1: Try WWW-Authenticate header method (preferred)
    console.log('Attempting WWW-Authenticate header discovery...');
    try {
      const metadata = await this.discoverViaWWWAuthenticate();
      if (metadata) {
        console.log('Successfully discovered via WWW-Authenticate header');
        return metadata;
      }
    } catch (error) {
      console.warn(
        'WWW-Authenticate discovery failed:',
        error instanceof Error ? error.message : String(error)
      );
    }

    // Step 2: Try well-known URI method
    console.log('Attempting well-known URI discovery...');

    const url = new URL(this.serverUrl);
    const urisToTry: string[] = [];

    // 1. Path A (Standard PRM, RFC 9728): [MCP Server Host]/.well-known/oauth-protected-resource
    // Try with path component if present (e.g. /public/mcp -> /.well-known/oauth-protected-resource/public/mcp)
    if (url.pathname !== '/' && url.pathname !== '') {
      const path = url.pathname.startsWith('/') ? url.pathname : `/${url.pathname}`;
      const cleanPath = path.replace(/\/$/, '');
      urisToTry.push(`${url.origin}/.well-known/oauth-protected-resource${cleanPath}`);
    }
    // Always try root well-known
    urisToTry.push(`${url.origin}/.well-known/oauth-protected-resource`);

    // 2. Path B (OAuth AS Metadata, RFC 8414): [MCP Server Host]/.well-known/oauth-authorization-server
    urisToTry.push(`${url.origin}/.well-known/oauth-authorization-server`);

    // 3. Path C (Root Host Discovery): [MCP Server Host]
    urisToTry.push(`${url.origin}`);

    const errors: string[] = [];

    for (const uri of urisToTry) {
      try {
        console.log(`Trying metadata URI: ${uri}`);
        const metadata = await this.fetchMetadata(uri);
        console.log('Successfully discovered via well-known URI');
        return metadata;
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        console.warn(`Failed to fetch metadata from ${uri}: ${msg}`);
        errors.push(`${uri}: ${msg}`);
      }
    }

    throw new Error(
      `Protected Resource Metadata discovery failed. Tried the following URIs:\n${errors.join('\n')}`
    );
  }

  /**
   * Discover metadata via WWW-Authenticate header
   */
  private async discoverViaWWWAuthenticate(): Promise<ProtectedResourceMetadata | null> {
    // Make a request to the server to trigger 401 with WWW-Authenticate header
    const response = await fetchWithDebug(this.serverUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream'
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: {
            name: 'dcr-test-client',
            version: '0.1.0'
          }
        },
        id: 1
      })
    });

    // Check for WWW-Authenticate header
    const wwwAuthHeader = response.headers.get('www-authenticate');
    if (!wwwAuthHeader) {
      return null;
    }

    // Extract resource_metadata URL
    const metadataUrl = parseWWWAuthenticateHeader(wwwAuthHeader);
    if (!metadataUrl) {
      return null;
    }

    // Fetch metadata from the URL
    return await this.fetchMetadata(metadataUrl);
  }

  /**
   * Fetch and validate metadata from a URL
   */
  private async fetchMetadata(url: string): Promise<ProtectedResourceMetadata> {
    const response = await fetchWithDebug(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json'
      },
      debugLabel: 'Protected Resource Metadata'
    });

    if (!response.ok) {
      throw new Error(`Metadata fetch failed: ${response.status} ${response.statusText}`);
    }

    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new Error(`Metadata endpoint returned non-JSON content type: ${contentType}`);
    }

    const metadata = await response.json();

    // Validate against RFC 9728 schema
    const validatedMetadata = ProtectedResourceMetadataSchema.parse(metadata);

    // Ensure authorization_servers is present
    if (
      !validatedMetadata.authorization_servers ||
      validatedMetadata.authorization_servers.length === 0
    ) {
      throw new Error('Protected resource metadata missing authorization_servers field');
    }

    return validatedMetadata;
  }

  /**
   * Get the first authorization server from metadata
   */
  async getAuthorizationServer(): Promise<string> {
    const metadata = await this.discover();
    return metadata.authorization_servers[0];
  }

  /**
   * Get all authorization servers from metadata
   */
  async getAuthorizationServers(): Promise<string[]> {
    const metadata = await this.discover();
    return metadata.authorization_servers;
  }
}
