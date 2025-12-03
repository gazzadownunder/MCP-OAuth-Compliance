/**
 * Client ID Metadata Document Handler
 *
 * Handles Client ID Metadata Document operations for MCP 2025-11-25 specification.
 * Client ID Metadata Documents allow using HTTPS URLs as client identifiers.
 *
 * @see MCP 2025-11-25 Authorization Specification
 */

import {
  ClientIDMetadataDocument,
  isValidClientIDUrl,
  fetchClientIDMetadataDocument,
  validateClientIDMetadataDocument
} from '../types/client-id-metadata.js';

export interface RegistrationResult {
  success: boolean;
  clientId: string;
  metadata?: ClientIDMetadataDocument;
  error?: string;
  errors?: string[];
  warnings?: string[];
}

export interface ValidationResult {
  valid: boolean;
  metadata?: ClientIDMetadataDocument;
  errors: string[];
  warnings: string[];
  debug?: {
    request?: {
      url?: string;
      method?: string;
      headers?: Record<string, string>;
    };
    response?: {
      status?: number;
      statusText?: string;
      headers?: Record<string, string>;
      body?: string;
    };
  };
}

/**
 * Client ID Metadata Document Handler
 *
 * Provides methods for validating and using Client ID Metadata Documents
 * as defined in MCP 2025-11-25.
 */
export class ClientIDMetadataHandler {
  /**
   * Register client using Client ID Metadata Document
   *
   * This method validates the metadata document and prepares it for use
   * with the authorization server.
   *
   * @param metadataDocumentUrl - HTTPS URL to the client metadata document
   * @returns Registration result with metadata or errors
   */
  async registerWithMetadata(metadataDocumentUrl: string): Promise<RegistrationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Step 1: Validate URL format
      if (!isValidClientIDUrl(metadataDocumentUrl)) {
        return {
          success: false,
          clientId: metadataDocumentUrl,
          error: 'Invalid Client ID Metadata URL: must be HTTPS with path component',
          errors: ['URL must use HTTPS protocol and include a path component']
        };
      }

      // Step 2: Fetch and validate metadata document
      const validationResult = await validateClientIDMetadataDocument(metadataDocumentUrl);

      if (!validationResult.valid || !validationResult.document) {
        return {
          success: false,
          clientId: metadataDocumentUrl,
          error: 'Failed to validate Client ID Metadata Document',
          errors: validationResult.errors,
          warnings: validationResult.warnings
        };
      }

      const metadata = validationResult.document;

      // Step 3: Verify client_id in document matches URL
      if (metadata.client_id !== metadataDocumentUrl) {
        errors.push(
          `client_id in metadata document ("${metadata.client_id}") must match the document URL ("${metadataDocumentUrl}")`
        );
        return {
          success: false,
          clientId: metadataDocumentUrl,
          error: 'client_id mismatch',
          errors,
          warnings: validationResult.warnings
        };
      }

      // Step 4: Additional validation warnings
      if (validationResult.warnings.length > 0) {
        warnings.push(...validationResult.warnings);
      }

      // Success
      return {
        success: true,
        clientId: metadataDocumentUrl,
        metadata,
        warnings: warnings.length > 0 ? warnings : undefined
      };
    } catch (error) {
      return {
        success: false,
        clientId: metadataDocumentUrl,
        error: `Registration failed: ${error instanceof Error ? error.message : String(error)}`,
        errors: [error instanceof Error ? error.message : String(error)]
      };
    }
  }

  /**
   * Validate metadata document meets MCP 2025-11-25 requirements
   *
   * @param metadataUrl - URL to the metadata document
   * @param enableDebug - Enable HTTP request/response debugging
   * @returns Validation result with metadata and any errors/warnings
   */
  async validateMetadata(metadataUrl: string, enableDebug: boolean = false): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // URL validation
      if (!isValidClientIDUrl(metadataUrl)) {
        errors.push('URL must use HTTPS protocol and include a path component');
        return { valid: false, errors, warnings };
      }

      // Fetch and validate document
      const result = await validateClientIDMetadataDocument(metadataUrl, enableDebug);

      return {
        valid: result.valid,
        metadata: result.document,
        errors: result.errors,
        warnings: result.warnings,
        debug: result.debug
      };
    } catch (error) {
      errors.push(`Validation failed: ${error instanceof Error ? error.message : String(error)}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Fetch metadata document without full validation
   *
   * Useful for retrieving the document to inspect its contents.
   *
   * @param metadataUrl - URL to the metadata document
   * @returns The metadata document or throws error
   */
  async fetchMetadata(metadataUrl: string): Promise<ClientIDMetadataDocument> {
    if (!isValidClientIDUrl(metadataUrl)) {
      throw new Error('Invalid Client ID Metadata URL: must be HTTPS with path component');
    }

    return await fetchClientIDMetadataDocument(metadataUrl);
  }

  /**
   * Check if a client ID is a valid Client ID Metadata Document URL
   *
   * @param clientId - The client identifier to check
   * @returns true if it's a valid metadata document URL
   */
  isMetadataDocumentUrl(clientId: string): boolean {
    return isValidClientIDUrl(clientId);
  }

  /**
   * Extract redirect URIs from metadata document
   *
   * @param metadata - Client ID Metadata Document
   * @returns Array of redirect URIs
   */
  getRedirectUris(metadata: ClientIDMetadataDocument): string[] {
    return metadata.redirect_uris || [];
  }

  /**
   * Get client authentication method from metadata
   *
   * @param metadata - Client ID Metadata Document
   * @returns Authentication method (default: 'none' for public clients)
   */
  getAuthMethod(metadata: ClientIDMetadataDocument): string {
    return metadata.token_endpoint_auth_method || 'none';
  }

  /**
   * Check if client uses private_key_jwt authentication
   *
   * @param metadata - Client ID Metadata Document
   * @returns true if private_key_jwt is configured
   */
  usesPrivateKeyJWT(metadata: ClientIDMetadataDocument): boolean {
    return metadata.token_endpoint_auth_method === 'private_key_jwt';
  }

  /**
   * Get JWKS configuration for private_key_jwt
   *
   * @param metadata - Client ID Metadata Document
   * @returns JWKS URI or JWKS object
   */
  getJWKSConfig(metadata: ClientIDMetadataDocument): { jwks_uri?: string; jwks?: object } {
    return {
      jwks_uri: metadata.jwks_uri,
      jwks: metadata.jwks
    };
  }
}
