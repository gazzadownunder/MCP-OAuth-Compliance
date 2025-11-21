import {
  AuthorizationServerMetadata,
  AuthorizationServerMetadataSchema,
  getWellKnownUri
} from '../types/oauth-discovery.js';

/**
 * OAuth 2.0 Authorization Server Metadata Discovery Client
 * Implements RFC 8414
 */
export class DiscoveryClient {
  private issuerUrl: string;

  constructor(issuerUrl: string) {
    this.issuerUrl = issuerUrl;
  }

  /**
   * Discover authorization server metadata
   * Implements RFC 8414 Section 3
   */
  async discover(): Promise<AuthorizationServerMetadata> {
    const wellKnownUri = getWellKnownUri(this.issuerUrl);

    try {
      const response = await fetch(wellKnownUri, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(
          `Discovery failed: ${response.status} ${response.statusText} at ${wellKnownUri}`
        );
      }

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error(`Discovery endpoint returned non-JSON content type: ${contentType}`);
      }

      const metadata = await response.json();

      // Validate against RFC 8414 schema
      const validatedMetadata = AuthorizationServerMetadataSchema.parse(metadata);

      // Verify issuer matches (RFC 8414 Section 3)
      if (validatedMetadata.issuer !== this.issuerUrl) {
        throw new Error(
          `Issuer mismatch: expected ${this.issuerUrl}, got ${validatedMetadata.issuer}`
        );
      }

      return validatedMetadata;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`OAuth Discovery failed: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Get the registration endpoint from server metadata
   */
  async getRegistrationEndpoint(): Promise<string> {
    const metadata = await this.discover();

    if (!metadata.registration_endpoint) {
      throw new Error('Server does not support dynamic client registration (no registration_endpoint in metadata)');
    }

    return metadata.registration_endpoint;
  }

  /**
   * Get all endpoints from server metadata
   */
  async getEndpoints(): Promise<{
    issuer: string;
    authorization?: string;
    token?: string;
    registration?: string;
    revocation?: string;
    introspection?: string;
    jwks?: string;
  }> {
    const metadata = await this.discover();

    return {
      issuer: metadata.issuer,
      authorization: metadata.authorization_endpoint,
      token: metadata.token_endpoint,
      registration: metadata.registration_endpoint,
      revocation: metadata.revocation_endpoint,
      introspection: metadata.introspection_endpoint,
      jwks: metadata.jwks_uri
    };
  }

  /**
   * Check if server supports a specific grant type
   */
  async supportsGrantType(grantType: string): Promise<boolean> {
    const metadata = await this.discover();
    return metadata.grant_types_supported?.includes(grantType) ?? false;
  }

  /**
   * Check if server supports a specific response type
   */
  async supportsResponseType(responseType: string): Promise<boolean> {
    const metadata = await this.discover();
    return metadata.response_types_supported?.includes(responseType) ?? false;
  }
}
