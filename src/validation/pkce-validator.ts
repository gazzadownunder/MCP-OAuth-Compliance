/**
 * PKCE (Proof Key for Code Exchange) Validator
 *
 * Validates PKCE support and enforcement according to:
 * - RFC 7636: Proof Key for Code Exchange
 * - MCP 2025-11-25: Requires S256 code challenge method
 */

import { ProtocolVersion } from '../types/protocol-version.js';
import { AuthorizationServerMetadata } from '../types/oauth-discovery.js';

export interface ValidationResult {
  compliant: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * PKCE Validator
 * Validates PKCE configuration and enforcement based on protocol version
 */
export class PKCEValidator {
  private protocolVersion: ProtocolVersion;

  constructor(protocolVersion: ProtocolVersion = ProtocolVersion.PRE_2025_11_25) {
    this.protocolVersion = protocolVersion;
  }

  /**
   * Validate PKCE support in authorization server metadata
   *
   * @param metadata - Authorization server metadata
   * @returns Validation result with errors and warnings
   */
  validatePKCESupport(metadata: AuthorizationServerMetadata): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check if code_challenge_methods_supported is present
    if (!metadata.code_challenge_methods_supported) {
      errors.push('code_challenge_methods_supported not found in authorization server metadata');
      return { compliant: false, errors, warnings };
    }

    // Check if array is empty
    if (metadata.code_challenge_methods_supported.length === 0) {
      errors.push('code_challenge_methods_supported is empty - PKCE not supported');
      return { compliant: false, errors, warnings };
    }

    // Protocol-specific validation
    if (this.protocolVersion === ProtocolVersion.MCP_2025_11_25) {
      return this.validateMCP2025PKCE(metadata.code_challenge_methods_supported, errors, warnings);
    } else {
      return this.validateLegacyPKCE(metadata.code_challenge_methods_supported, errors, warnings);
    }
  }

  /**
   * Validate PKCE for MCP 2025-11-25 (S256 required)
   */
  private validateMCP2025PKCE(
    methods: string[],
    errors: string[],
    warnings: string[]
  ): ValidationResult {
    // S256 is REQUIRED for MCP 2025-11-25
    if (!methods.includes('S256')) {
      errors.push('S256 code challenge method is REQUIRED for MCP 2025-11-25');
    }

    // Plain method is discouraged
    if (methods.includes('plain')) {
      warnings.push(
        'Plain PKCE method is discouraged in MCP 2025-11-25. ' +
        'S256 should be used for enhanced security.'
      );
    }

    // Check for unknown methods
    const validMethods = ['S256', 'plain'];
    const unknownMethods = methods.filter(m => !validMethods.includes(m));
    if (unknownMethods.length > 0) {
      warnings.push(
        `Unknown code challenge methods: ${unknownMethods.join(', ')}. ` +
        'Only S256 and plain are defined in RFC 7636.'
      );
    }

    return {
      compliant: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate PKCE for pre-2025-11-25 (S256 or plain acceptable)
   */
  private validateLegacyPKCE(
    methods: string[],
    errors: string[],
    warnings: string[]
  ): ValidationResult {
    // For legacy, just check if PKCE is supported
    const validMethods = ['S256', 'plain'];
    const supportedMethods = methods.filter(m => validMethods.includes(m));

    if (supportedMethods.length === 0) {
      warnings.push(
        'No standard PKCE methods (S256 or plain) supported. ' +
        'PKCE is recommended for OAuth 2.1 compliance.'
      );
    } else if (!methods.includes('S256')) {
      warnings.push(
        'S256 code challenge method not supported. ' +
        'S256 is recommended over plain for enhanced security.'
      );
    }

    return {
      compliant: true, // PKCE is optional for pre-2025-11-25
      errors,
      warnings
    };
  }

  /**
   * Validate code challenge method parameter
   *
   * @param method - The code challenge method being used
   * @returns Validation result
   */
  validateCodeChallengeMethod(method: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!method) {
      errors.push('code_challenge_method is required when using PKCE');
      return { compliant: false, errors, warnings };
    }

    // Check if method is valid
    const validMethods = ['S256', 'plain'];
    if (!validMethods.includes(method)) {
      errors.push(
        `Invalid code_challenge_method: "${method}". ` +
        'Must be "S256" or "plain" per RFC 7636.'
      );
      return { compliant: false, errors, warnings };
    }

    // Protocol-specific validation
    if (this.protocolVersion === ProtocolVersion.MCP_2025_11_25) {
      if (method !== 'S256') {
        errors.push(
          'code_challenge_method must be "S256" for MCP 2025-11-25. ' +
          'Plain method is not allowed.'
        );
        return { compliant: false, errors, warnings };
      }
    } else {
      // For legacy, warn if using plain
      if (method === 'plain') {
        warnings.push(
          'Using "plain" code challenge method. ' +
          'Consider using "S256" for enhanced security.'
        );
      }
    }

    return {
      compliant: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate code challenge format
   *
   * @param codeChallenge - The code challenge value
   * @param method - The code challenge method
   * @returns Validation result
   */
  validateCodeChallenge(codeChallenge: string, method: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!codeChallenge) {
      errors.push('code_challenge is required when using PKCE');
      return { compliant: false, errors, warnings };
    }

    // Validate format based on method
    if (method === 'S256') {
      // S256: Base64-URL encoded SHA256 hash (43-128 characters)
      const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
      if (!base64UrlRegex.test(codeChallenge)) {
        errors.push(
          'code_challenge must be base64-URL encoded for S256 method ' +
          '(unreserved characters only: [A-Za-z0-9_-])'
        );
      }

      if (codeChallenge.length < 43 || codeChallenge.length > 128) {
        errors.push(
          `code_challenge length must be 43-128 characters for S256, got ${codeChallenge.length}`
        );
      }
    } else if (method === 'plain') {
      // Plain: 43-128 unreserved characters
      const unreservedRegex = /^[A-Za-z0-9._~-]+$/;
      if (!unreservedRegex.test(codeChallenge)) {
        errors.push(
          'code_challenge must contain only unreserved characters for plain method ' +
          '([A-Za-z0-9._~-])'
        );
      }

      if (codeChallenge.length < 43 || codeChallenge.length > 128) {
        errors.push(
          `code_challenge length must be 43-128 characters, got ${codeChallenge.length}`
        );
      }
    }

    return {
      compliant: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate code verifier format (used in token request)
   *
   * @param codeVerifier - The code verifier value
   * @returns Validation result
   */
  validateCodeVerifier(codeVerifier: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!codeVerifier) {
      errors.push('code_verifier is required in token request when PKCE is used');
      return { compliant: false, errors, warnings };
    }

    // Verifier: 43-128 unreserved characters
    const unreservedRegex = /^[A-Za-z0-9._~-]+$/;
    if (!unreservedRegex.test(codeVerifier)) {
      errors.push(
        'code_verifier must contain only unreserved characters ' +
        '([A-Za-z0-9._~-] per RFC 7636)'
      );
    }

    if (codeVerifier.length < 43 || codeVerifier.length > 128) {
      errors.push(
        `code_verifier length must be 43-128 characters, got ${codeVerifier.length}`
      );
    }

    return {
      compliant: errors.length === 0,
      errors,
      warnings
    };
  }
}
