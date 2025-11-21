/**
 * MCP Authorization Flow Compliance Testing Types
 * Tests compliance with RFC 9728, RFC 8414, RFC 7591, and OAuth 2.1
 */

export type TestStatus = 'pass' | 'fail' | 'skip' | 'warning' | 'pending' | 'info';

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

export enum ComplianceCategory {
  PROTECTED_RESOURCE_METADATA = '1. Protected Resource Metadata (RFC 9728)',
  AS_DISCOVERY = '2. Authorization Server Discovery (RFC 8414)',
  DCR = '3. Dynamic Client Registration (RFC 7591)',
  OAUTH_FLOW = '4. OAuth 2.1 + PKCE Flow',
  JWT_VALIDATION = '5. JWT Access Token Validation (RFC 9068)',
  PROTECTED_ACCESS = '6. Protected Resource Access',
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
  scope?: string; // OAuth scopes to request (optional)
  timeout?: number;
}
