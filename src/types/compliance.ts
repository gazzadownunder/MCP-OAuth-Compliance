/**
 * MCP Authorization Flow Compliance Testing Types
 * Tests compliance with RFC 9728, RFC 8414, RFC 7591, and OAuth 2.1
 * Supports both pre-2025-11-25 and MCP 2025-11-25 specifications
 */

import { ProtocolVersion } from './protocol-version.js';

export type TestStatus = 'pass' | 'fail' | 'skip' | 'warning' | 'pending' | 'info';

/**
 * Client Registration Methods (MCP 2025-11-25)
 * Defines the priority order for client registration
 */
export enum ClientRegistrationMethod {
  /** Priority 1: Use existing pre-configured credentials */
  PREREGISTERED = 'Preregistration',
  /** Priority 2: Client ID Metadata Document (MCP 2025-11-25 only) */
  CLIENT_ID_METADATA_DOCUMENT = 'Client ID Metadata Document',
  /** Priority 3: Dynamic Client Registration (RFC 7591) - fallback */
  DYNAMIC_CLIENT_REGISTRATION = 'Dynamic Client Registration (RFC 7591)'
}

export interface ComplianceTestResult {
  id: string;
  category: string;
  requirement: string;
  status: TestStatus;
  message?: string;
  details?: Record<string, unknown>;
  timestamp: Date;
  rfcReference?: string;
  rfcUrl?: string;
  expected?: string;
  actual?: string;
  remediation?: string;
  indentLevel?: number; // 0 = no indent, 1 = first level, 2 = second level, etc.
  groupLabel?: string; // Optional label for grouped tests (e.g., "MCP 4.2.1", "MCP 4.2.2")

  /** NEW: For CLIENT_REGISTRATION category - indicates which registration method was used */
  registrationMethod?: ClientRegistrationMethod;

  debug?: {
    request?: {
      url?: string;
      method?: string;
      headers?: Record<string, string>;
      body?: unknown;
    };
    response?: {
      status?: number;
      statusText?: string;
      headers?: Record<string, string>;
      body?: unknown;
    };
  };
}

export interface ComplianceTestSuite {
  serverUrl: string;
  startTime: Date;
  endTime?: Date;
  results: ComplianceTestResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
    pending: number;
  };
}

/**
 * Compliance Test Categories
 * Supports both pre-2025-11-25 and MCP 2025-11-25 protocols
 */
export enum ComplianceCategory {
  // Core categories (both protocols) - Aligned with MCP 2025-11-25 specification sections
  PROTECTED_RESOURCE_METADATA = 'MCP 4.2: Protected Resource Metadata Discovery (RFC 9728)',
  AS_DISCOVERY = 'MCP 4.3: Authorization Server Discovery (RFC 8414)',

  /** UNIFIED: Client Registration (replaces DCR category) */
  CLIENT_REGISTRATION = 'MCP 5: Client Registration',

  OAUTH_FLOW = 'MCP 7: Authorization Flow',
  JWT_VALIDATION = 'MCP 9: Access Token Usage (RFC 9068)',
  PROTECTED_ACCESS = 'MCP 9.2: Token Handling',

  /** MCP Server Capabilities Discovery */
  SERVER_CAPABILITIES = 'Server Capabilities Discovery',

  // NEW: MCP 2025-11-25 specific categories
  /** S256 PKCE enforcement (MCP 2025-11-25) */
  PKCE_ENFORCEMENT = 'MCP 12.4: PKCE Authorization Code Protection',

  /** RFC 8707 Resource Indicators (MCP 2025-11-25) */
  RESOURCE_PARAMETER = 'MCP 8: Resource Parameter Implementation (RFC 8707)',

  /** Token audience validation (MCP 2025-11-25) */
  TOKEN_AUDIENCE = 'MCP 12.1: Token Audience Binding and Validation',

  /** Step-up authorization (MCP 2025-11-25) */
  STEP_UP_AUTH = 'MCP 11: Scope Challenge Handling (Step-Up Authorization)',

  /** Private Key JWT authentication (MCP 2025-11-25) */
  PRIVATE_KEY_JWT = 'MCP 13: Private Key JWT Authentication',

  // Legacy category for backward compatibility
  /** @deprecated Use CLIENT_REGISTRATION instead */
  DCR = 'MCP 5.3: Dynamic Client Registration (RFC 7591)'
}

export interface ComplianceTest {
  id: string;
  category: ComplianceCategory;
  requirement: string;
  test: () => Promise<ComplianceTestResult>;
  dependsOn?: string[];
}

export interface ServerTestConfig {
  serverUrl: string;

  // Protocol version selection (NEW)
  /** MCP authorization protocol version to test against */
  protocolVersion?: ProtocolVersion;

  // Test control flags
  skipDCR?: boolean;
  skipOAuthFlow?: boolean;
  interactiveAuth?: boolean; // Enable interactive OAuth flow testing (requires browser)
  callbackPort?: number; // Port for OAuth callback server (default: 3000)
  redirectUri?: string; // Full redirect URI (e.g., http://localhost:8082/) - overrides callbackPort
  resourceUri?: string; // Resource URI for RFC 8707 testing

  // Pre-configured client mode - bypasses DCR, uses browser for IDP authentication
  usePreConfiguredClient?: boolean; // Use pre-configured client_id instead of DCR
  clientId?: string; // Pre-configured client_id (when usePreConfiguredClient=true)
  clientSecret?: string; // Pre-configured client_secret (optional)

  // OAuth parameters
  scope?: string; // OAuth scopes to request (optional)

  // MCP 2025-11-25 specific options (NEW)
  /** Use Client ID Metadata Document (HTTPS URL as client_id) */
  useClientIDMetadata?: boolean;
  /** URL to Client ID Metadata Document */
  clientIDMetadataUrl?: string;
  /** Enforce S256 PKCE (required for 2025-11-25) */
  enforceS256?: boolean;
  /** RFC 8707 resource parameter */
  resourceParameter?: string;
  /** Optional: Tool name for scope challenge test (step-1.5) */
  privilegedToolName?: string;

  // Preregistration client options (both protocols)
  preregisteredClient?: {
    clientId: string;
    clientSecret?: string;
    redirectUri: string;
  };

  // Debug and timeout
  enableDebug?: boolean; // Enable debug mode to capture request/response data
  timeout?: number;

  // MCP Server Capabilities
  /** Allow HTTP transport for authenticated MCP server connections (default: false, HTTPS only) */
  allowHttpMcpConnection?: boolean;
}
