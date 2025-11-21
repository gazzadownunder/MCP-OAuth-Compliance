import { ValidationResult, RegistrationResponse, ClientMetadata } from '../types/dcr.js';

/**
 * Validates RFC 7591 compliance for client registration responses
 */
export class RFC7591Validator {
  /**
   * Validate a registration response for RFC 7591 compliance
   */
  validateRegistrationResponse(response: RegistrationResponse): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Required field: client_id
    if (!response.client_id) {
      errors.push('Missing required field: client_id');
    }

    // Validate client_secret_expires_at
    if (response.client_secret_expires_at !== undefined) {
      if (response.client_secret_expires_at < 0) {
        errors.push('client_secret_expires_at must be non-negative');
      }

      // If expires_at is 0, client_secret should not expire
      if (response.client_secret_expires_at === 0 && !response.client_secret) {
        warnings.push('client_secret_expires_at is 0 but no client_secret provided');
      }
    }

    // Validate client_id_issued_at
    if (response.client_id_issued_at !== undefined && response.client_id_issued_at < 0) {
      errors.push('client_id_issued_at must be non-negative');
    }

    // Validate redirect URIs (must use https, localhost, or app-specific schemes)
    if (response.redirect_uris) {
      for (const uri of response.redirect_uris) {
        if (!this.isValidRedirectUri(uri)) {
          errors.push(`Invalid redirect_uri: ${uri} (must use https, localhost, or app-specific scheme)`);
        }
      }
    }

    // Validate grant_types and response_types consistency
    if (response.grant_types && response.response_types) {
      const hasAuthCodeGrant = response.grant_types.includes('authorization_code');
      const hasCodeResponse = response.response_types.some(rt => rt.includes('code'));

      if (hasAuthCodeGrant && !response.redirect_uris) {
        errors.push('authorization_code grant type requires redirect_uris');
      }

      if (hasCodeResponse && !hasAuthCodeGrant) {
        warnings.push('response_type includes code but authorization_code grant not specified');
      }
    }

    // Validate URIs are properly formed
    const uriFields: Array<keyof RegistrationResponse> = [
      'client_uri',
      'logo_uri',
      'tos_uri',
      'policy_uri',
      'jwks_uri',
      'registration_client_uri'
    ];

    for (const field of uriFields) {
      const value = response[field];
      if (value && typeof value === 'string' && !this.isValidUri(value)) {
        errors.push(`Invalid URI in field ${field}: ${value}`);
      }
    }

    // Validate contacts are email addresses
    if (response.contacts) {
      for (const contact of response.contacts) {
        if (!this.isValidEmail(contact)) {
          errors.push(`Invalid email in contacts: ${contact}`);
        }
      }
    }

    // Check for registration management endpoint consistency
    if (response.registration_client_uri && !response.registration_access_token) {
      warnings.push('registration_client_uri provided without registration_access_token');
    }

    return {
      compliant: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate client metadata for registration request
   */
  validateClientMetadata(metadata: ClientMetadata): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check if redirect_uris is required
    const requiresRedirectUris = metadata.grant_types?.some(
      gt => gt === 'authorization_code' || gt === 'implicit'
    ) || metadata.response_types?.some(rt => rt.includes('code') || rt.includes('token'));

    if (requiresRedirectUris && !metadata.redirect_uris) {
      errors.push('redirect_uris is required for redirect-based flows');
    }

    // Validate redirect URIs
    if (metadata.redirect_uris) {
      for (const uri of metadata.redirect_uris) {
        if (!this.isValidRedirectUri(uri)) {
          errors.push(`Invalid redirect_uri: ${uri}`);
        }
      }
    }

    // Validate token_endpoint_auth_method consistency
    if (metadata.token_endpoint_auth_method) {
      const jwtMethods = ['client_secret_jwt', 'private_key_jwt'];
      if (jwtMethods.includes(metadata.token_endpoint_auth_method)) {
        if (!metadata.jwks_uri && !metadata.jwks) {
          warnings.push(`${metadata.token_endpoint_auth_method} requires jwks_uri or jwks`);
        }
      }
    }

    // Validate grant_types and response_types
    if (metadata.grant_types && metadata.response_types) {
      const implicitGrant = metadata.grant_types.includes('implicit');
      const tokenResponse = metadata.response_types.some(rt => rt.includes('token'));

      if (implicitGrant !== tokenResponse) {
        warnings.push('Inconsistent grant_types and response_types for implicit flow');
      }
    }

    return {
      compliant: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate a redirect URI according to RFC 7591 Section 2
   */
  private isValidRedirectUri(uri: string): boolean {
    try {
      const url = new URL(uri);

      // Must use https, localhost http, or custom scheme
      if (url.protocol === 'https:') {
        return true;
      }

      if (url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1')) {
        return true;
      }

      // Custom schemes for native apps (not http/https)
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return true;
      }

      return false;
    } catch {
      return false;
    }
  }

  /**
   * Validate a URI
   */
  private isValidUri(uri: string): boolean {
    try {
      new URL(uri);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Validate an email address
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}
