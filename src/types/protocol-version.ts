/**
 * MCP Authorization Protocol Version Support
 *
 * This module defines protocol version enumerations and configuration
 * to support both the legacy (pre-2025-11-25) and updated (2025-11-25)
 * MCP authorization specifications.
 */

/**
 * Supported MCP authorization protocol versions
 */
export enum ProtocolVersion {
  /**
   * Original MCP OAuth specification
   * - Optional PKCE (S256 or plain)
   * - DCR-based client registration (RFC 7591)
   * - Standard OAuth 2.0/2.1 flows
   */
  PRE_2025_11_25 = 'pre-2025-11-25',

  /**
   * MCP 2025-11-25 specification
   * - Required S256 PKCE
   * - Client ID Metadata Documents (HTTPS URLs as client IDs)
   * - Resource parameter (RFC 8707)
   * - Token audience validation
   * - Scope selection strategy
   * - Step-up authorization
   * - Private Key JWT authentication
   */
  MCP_2025_11_25 = '2025-11-25'
}

/**
 * Protocol-specific feature configuration
 *
 * This interface defines which features are enabled/required
 * for a given protocol version.
 */
export interface ProtocolConfig {
  /**
   * The protocol version being used
   */
  version: ProtocolVersion;

  /**
   * Enforce S256 PKCE code challenge method
   * - Pre-2025-11-25: false (S256 or plain allowed)
   * - MCP 2025-11-25: true (S256 required)
   */
  enforceS256PKCE: boolean;

  /**
   * Require resource parameter in authorization/token requests (RFC 8707)
   * - Pre-2025-11-25: false
   * - MCP 2025-11-25: true
   */
  requireResourceParameter: boolean;

  /**
   * Enforce token audience validation
   * - Pre-2025-11-25: false
   * - MCP 2025-11-25: true
   */
  enforceTokenAudience: boolean;

  /**
   * Support Client ID Metadata Documents
   * - Pre-2025-11-25: false
   * - MCP 2025-11-25: true
   */
  supportClientIDMetadata: boolean;

  /**
   * Support step-up authorization (insufficient_scope handling)
   * - Pre-2025-11-25: false
   * - MCP 2025-11-25: true
   */
  supportStepUpAuth: boolean;

  /**
   * Require private_key_jwt authentication method support
   * - Pre-2025-11-25: false
   * - MCP 2025-11-25: true (as an option)
   */
  requirePrivateKeyJWT: boolean;
}

/**
 * Get default protocol configuration for a given version
 */
export function getProtocolConfig(version: ProtocolVersion): ProtocolConfig {
  switch (version) {
    case ProtocolVersion.PRE_2025_11_25:
      return {
        version,
        enforceS256PKCE: false,
        requireResourceParameter: false,
        enforceTokenAudience: false,
        supportClientIDMetadata: false,
        supportStepUpAuth: false,
        requirePrivateKeyJWT: false
      };

    case ProtocolVersion.MCP_2025_11_25:
      return {
        version,
        enforceS256PKCE: true,
        requireResourceParameter: true,
        enforceTokenAudience: true,
        supportClientIDMetadata: true,
        supportStepUpAuth: true,
        requirePrivateKeyJWT: false // Optional, not required
      };

    default:
      // Default to pre-2025-11-25 for backward compatibility
      return getProtocolConfig(ProtocolVersion.PRE_2025_11_25);
  }
}

/**
 * Check if a protocol version supports a specific feature
 */
export function supportsFeature(
  version: ProtocolVersion,
  feature: keyof Omit<ProtocolConfig, 'version'>
): boolean {
  const config = getProtocolConfig(version);
  return config[feature];
}
