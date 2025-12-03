/**
 * PKCE Enforcement Tests (MCP 2025-11-25)
 *
 * Tests S256 PKCE enforcement as required by MCP 2025-11-25.
 */

import {
  ComplianceTestResult,
  ComplianceCategory,
  ServerTestConfig
} from '../types/compliance.js';
import { ProtocolVersion } from '../types/protocol-version.js';
import { PKCEValidator } from '../validation/pkce-validator.js';

/**
 * Run PKCE enforcement tests
 *
 * @param config - Test configuration
 * @param asMetadata - Authorization server metadata (from cache)
 * @returns Test results
 */
export async function runPKCETests(
  config: ServerTestConfig,
  asMetadata: Record<string, any> | undefined
): Promise<ComplianceTestResult[]> {
  const results: ComplianceTestResult[] = [];
  const protocolVersion = config.protocolVersion || ProtocolVersion.PRE_2025_11_25;
  const validator = new PKCEValidator(protocolVersion);

  // Header
  results.push({
    id: 'pkce-header',
    category: ComplianceCategory.PKCE_ENFORCEMENT,
    requirement: 'PKCE S256 Enforcement',
    status: 'info',
    message: `Protocol version: ${protocolVersion}`,
    timestamp: new Date(),
    indentLevel: 0
  });

  // Check if authorization server metadata is available
  if (!asMetadata) {
    results.push({
      id: 'pkce-1',
      category: ComplianceCategory.PKCE_ENFORCEMENT,
      requirement: 'Authorization server metadata available',
      status: 'skip',
      message: 'Authorization server metadata not available',
      timestamp: new Date(),
      indentLevel: 1
    });
    return results;
  }

  const metadata = asMetadata;

  // Test 1: PKCE support advertised
  const pkceMethods = metadata.code_challenge_methods_supported;
  results.push({
    id: 'pkce-1',
    category: ComplianceCategory.PKCE_ENFORCEMENT,
    requirement: 'code_challenge_methods_supported advertised',
    status: pkceMethods && pkceMethods.length > 0 ? 'pass' : 'fail',
    message: pkceMethods
      ? `Advertised methods: ${pkceMethods.join(', ')}`
      : 'code_challenge_methods_supported not found in metadata',
    timestamp: new Date(),
    indentLevel: 1,
    rfcReference: 'RFC 7636 Section 4.3',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7636#section-4.3'
  });

  if (!pkceMethods || pkceMethods.length === 0) {
    return results;
  }

  // Test 2: Validate PKCE support
  const validationResult = validator.validatePKCESupport(metadata as any);

  results.push({
    id: 'pkce-2',
    category: ComplianceCategory.PKCE_ENFORCEMENT,
    requirement: 'PKCE validation',
    status: validationResult.compliant ? 'pass' : 'fail',
    message: validationResult.compliant
      ? 'PKCE configuration is valid'
      : `Validation errors: ${validationResult.errors.join(', ')}`,
    timestamp: new Date(),
    indentLevel: 1,
    details: {
      errors: validationResult.errors,
      warnings: validationResult.warnings
    }
  });

  // Test 3: S256 support (REQUIRED for MCP 2025-11-25)
  const supportsS256 = pkceMethods.includes('S256');

  if (protocolVersion === ProtocolVersion.MCP_2025_11_25) {
    results.push({
      id: 'pkce-3',
      category: ComplianceCategory.PKCE_ENFORCEMENT,
      requirement: 'S256 code challenge method (REQUIRED)',
      status: supportsS256 ? 'pass' : 'fail',
      message: supportsS256
        ? 'S256 is supported (MCP 2025-11-25 compliant)'
        : 'S256 is REQUIRED for MCP 2025-11-25 but not advertised',
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'MCP 2025-11-25 Specification',
      expected: 'code_challenge_methods_supported includes "S256"',
      actual: `Supported methods: ${pkceMethods.join(', ')}`,
      remediation: 'Configure authorization server to support S256 PKCE method'
    });
  } else {
    results.push({
      id: 'pkce-3',
      category: ComplianceCategory.PKCE_ENFORCEMENT,
      requirement: 'S256 code challenge method (recommended)',
      status: supportsS256 ? 'pass' : 'warning',
      message: supportsS256
        ? 'S256 is supported'
        : 'S256 is recommended but not required for pre-2025-11-25',
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 7636 Section 4.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7636#section-4.2'
    });
  }

  // Test 4: Plain method check
  const supportsPlain = pkceMethods.includes('plain');

  if (supportsPlain) {
    results.push({
      id: 'pkce-4',
      category: ComplianceCategory.PKCE_ENFORCEMENT,
      requirement: 'Plain code challenge method',
      status: protocolVersion === ProtocolVersion.MCP_2025_11_25 ? 'warning' : 'info',
      message: protocolVersion === ProtocolVersion.MCP_2025_11_25
        ? 'Server advertises plain method - S256 is recommended for MCP 2025-11-25'
        : 'Server advertises plain method support',
      timestamp: new Date(),
      indentLevel: 1,
      rfcReference: 'RFC 7636 Section 4.2',
      rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7636#section-4.2'
    });
  }

  // Display warnings
  if (validationResult.warnings.length > 0) {
    validationResult.warnings.forEach((warning: string, index: number) => {
      results.push({
        id: `pkce-warning-${index + 1}`,
        category: ComplianceCategory.PKCE_ENFORCEMENT,
        requirement: 'PKCE configuration warning',
        status: 'warning',
        message: warning,
        timestamp: new Date(),
        indentLevel: 2
      });
    });
  }

  return results;
}
