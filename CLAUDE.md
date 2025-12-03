# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP OAuth Compliance Tester validates MCP server OAuth compliance with RFC 9728, RFC 8414, RFC 7591, OAuth 2.1, and **MCP 2025-11-25 specification**.

**Protocol Version**: Tests against **MCP 2025-11-25** by default, with backward compatibility for pre-2025-11-25 implementations.

**IMPORTANT**: DCR is NOT part of MCP. This client uses MCP only for discovery (RFC 9728). The actual DCR operations are pure OAuth/HTTP requests.

### How It Works

1. **Discovery via MCP** (RFC 9728): MCP server advertises its authorization server
2. **OAuth Discovery** (RFC 8414): Authorization server advertises registration endpoint
3. **Client Registration**: Preregistration, Client ID Metadata Documents, or DCR (RFC 7591/7592)
4. **OAuth Flow**: Authorization code flow with PKCE, resource parameters, and token audience validation

## Protocol Version Support

This compliance tester supports both the original and updated MCP authorization protocols:

### Pre-2025-11-25 (Original MCP OAuth)

The original MCP OAuth specification supporting standard DCR and OAuth flows.

**Key Features**:
- RFC 7591 Dynamic Client Registration (DCR)
- Optional PKCE (S256 or plain methods allowed)
- Standard OAuth 2.0/2.1 authorization flows
- JWT access token validation
- Client registration via DCR or preregistration

### MCP 2025-11-25 (Enhanced Security) 🆕

Enhanced specification with improved security and new capabilities required for MCP authorization.

**New Requirements**:
- ✅ **S256 PKCE (REQUIRED)**: Mandatory S256 code challenge method, plain discouraged
- ✅ **Client ID Metadata Documents**: HTTPS URLs as client identifiers with hosted metadata
- ✅ **Resource Parameter (RFC 8707)**: Resource indicators in authorization/token requests
- ✅ **Token Audience Validation**: Strict JWT `aud` claim verification
- ✅ **Step-Up Authorization**: Handle `insufficient_scope` with re-authorization flow
- ✅ **Private Key JWT**: Enhanced client authentication option

**Client Registration Priority (MCP 2025-11-25)**:
1. **Preregistration** (Priority 1) - Use existing client credentials when available
2. **Client ID Metadata Document** (Priority 2) - HTTPS URL as client_id
3. **Dynamic Client Registration** (Priority 3) - RFC 7591 fallback

### Protocol Comparison

| Feature | Pre-2025-11-25 | MCP 2025-11-25 |
|---------|----------------|----------------|
| **Client Registration Methods** | DCR + Preregistration | Preregistration + Client ID Metadata + DCR (priority order) |
| **PKCE** | Optional (S256 or plain) | **REQUIRED** (S256 only) |
| **Resource Parameter** | Not required | **REQUIRED** (RFC 8707) |
| **Token Audience** | Not validated | **REQUIRED** (strict aud validation) |
| **Step-up Auth** | Not supported | **REQUIRED** (insufficient_scope handling) |
| **Client Auth** | Standard OAuth | Standard OAuth + private_key_jwt |

## Development Commands

### Setup
```bash
npm install
```

### Development
```bash
npm start                # Run the compliance tester web interface (http://localhost:3030)
npm run type-check       # Type check without emitting files
```

### Web Interface Features
- **Three-Column Layout**: Configuration (left), Test Results (center), OAuth Flow Readiness Overview (right)
- **OAuth Flow Readiness Panel**: Real-time overview showing whether each section provides sufficient compliance for OAuth authentication
  - Server Discovery (RFC 9728)
  - AS Metadata (RFC 8414)
  - Client Registration (Preregistration, Client ID Metadata, DCR)
  - Authorization Flow (OAuth 2.1 with PKCE)
  - PKCE Support (S256 enforcement for MCP 2025-11-25)
  - Token Validation (JWT validation)
  - Server Access (End-to-End) - Ultimate proof of successful authentication
- **Collapsible Test Sections**: Test results organized by MCP specification sections with expand/collapse controls
- **Persistent UI State**: Section preferences saved to localStorage and maintained across test runs
- **Visual Indicators**: Arrow icons (▼ expanded, ▶ collapsed) on left side of section headers
- **Smooth Animations**: CSS transitions for collapsing/expanding sections
- **Result Filtering**: Click summary cards to filter by status (Pass/Fail/Warning/Info/Skip)
- **Independent Control**: Each category section can be collapsed/expanded independently
- **Interactive OAuth Flow**: Enabled by default with expandable options
- **Full-Width Layout**: Panels use entire browser width for maximum visibility
- **Responsive Design**: Overview panel hidden on smaller screens (< 1400px width)
- **Auto-Hide Overview**: OAuth Flow Readiness panel hidden until tests are run

### Build
```bash
npm run build           # Compile TypeScript to JavaScript
```

### Testing
```bash
npm test                # Run all tests
npm run test:watch      # Run tests in watch mode
```

### Code Quality
```bash
npm run lint            # Check code with ESLint
npm run format          # Format code with Prettier
```

## MCP 2025-11-25 Features

### 1. Client ID Metadata Documents

**Module**: [src/types/client-id-metadata.ts](src/types/client-id-metadata.ts), [src/client/client-id-metadata-handler.ts](src/client/client-id-metadata-handler.ts)

HTTPS URLs as client identifiers that resolve to metadata documents.

**Key Functions**:
- `isValidClientIDUrl()` - Validates HTTPS URL format with path component
- `fetchClientIDMetadataDocument()` - Fetches and parses metadata document
- `validateClientIDMetadataDocument()` - Full validation with error reporting

**Usage**:
```typescript
const handler = new ClientIDMetadataHandler();
const result = await handler.registerWithMetadata('https://example.com/client');
```

### 2. PKCE S256 Enforcement

**Module**: [src/validation/pkce-validator.ts](src/validation/pkce-validator.ts)

Protocol-aware PKCE validation with S256 enforcement for MCP 2025-11-25.

**Key Functions**:
- `validatePKCESupport()` - Checks AS metadata for S256 support
- `validateCodeChallengeMethod()` - Enforces S256 for 2025-11-25
- `validateCodeChallenge()` - Format validation
- `validateCodeVerifier()` - Verifier validation

### 3. Resource Parameters (RFC 8707)

**Module**: [src/utils/oauth-flow.ts](src/utils/oauth-flow.ts)

Resource indicators for token audience binding.

**Key Functions**:
- `buildAuthorizationUrl()` - Includes resource parameter
- `exchangeCodeForToken()` - Sends resource in token request

**Usage**:
```typescript
const authUrl = buildAuthorizationUrl({
  // ... other params
  resource: 'https://mcp-server.example.com' // NEW
});
```

### 4. Token Audience Validation

**Module**: [src/validation/token-validator.ts](src/validation/token-validator.ts), [src/types/token.ts](src/types/token.ts)

Strict JWT audience claim verification for MCP 2025-11-25.

**Key Functions**:
- `validateAccessToken()` - Full token validation with audience check
- `validateAudience()` - Audience claim verification
- `validateResource()` - RFC 8707 resource claim validation

### 5. Step-Up Authorization

**Module**: [src/utils/step-up-auth.ts](src/utils/step-up-auth.ts), [src/compliance/step-up-auth-tests.ts](src/compliance/step-up-auth-tests.ts)

Handle `insufficient_scope` errors with re-authorization flow.

**Key Functions**:
- `detectInsufficientScope()` - Detect 403 insufficient_scope errors
- `parseRequiredScopes()` - Extract required scopes from error response
- `prepareReauthorization()` - Build new auth request with elevated scopes

### 6. Private Key JWT Authentication

**Module**: [src/compliance/private-key-jwt-tests.ts](src/compliance/private-key-jwt-tests.ts)

Enhanced client authentication using JWT assertions signed with client private keys.

**Tests**:
- AS advertisement of `private_key_jwt` support
- Client metadata JWKS requirements
- JWT assertion format validation
- Token endpoint authentication
- Signature verification

### 7. Server Capabilities Discovery

**Module**: [src/compliance/server-capabilities-tests.ts](src/compliance/server-capabilities-tests.ts)

End-to-end authentication verification by connecting to the MCP server with the obtained access token.

**Key Features**:
- Uses `StreamableHTTPClientTransport` for authenticated MCP connections
- Passes OAuth access token via Authorization header
- Tests connection to `/mcp` endpoint (not deprecated `/sse`)
- Auto-allows HTTP for localhost, requires option for non-localhost
- Lists available tools, resources, and prompts
- Runs LAST after all OAuth tests complete
- Ultimate proof that OAuth flow worked end-to-end

**Tests**:
- `cap-10.1`: Initialize authenticated MCP client connection
- `cap-10.2`: List available tools
- `cap-10.3`: List available resources
- `cap-10.4`: List available prompts

**HTTP Connection Handling**:
- Localhost (127.0.0.1, localhost, ::1) - HTTP always allowed
- Non-localhost - Requires "Allow HTTP MCP Connection" option enabled

## Architecture

### Protocol-Aware Design

The codebase uses a **protocol version** pattern to support both specifications:

```typescript
export enum ProtocolVersion {
  PRE_2025_11_25 = 'pre-2025-11-25',
  MCP_2025_11_25 = '2025-11-25'
}
```

**Key Principles**:
1. **Validators accept protocol version** in constructor
2. **Tests adapt based on protocol version**
3. **Backward compatibility maintained** for pre-2025-11-25
4. **Feature flags** control version-specific behavior

### Core Components

1. **DCRClient** ([src/client/dcr-client.ts](src/client/dcr-client.ts))
   - Main client class for interacting with MCP servers
   - **Protocol-aware**: Accepts `protocolVersion` in config
   - Manages connection lifecycle via MCP SDK's StdioClientTransport
   - Implements RFC 7591 operations: register, read, update, delete
   - Supports Client ID Metadata Documents (2025-11-25)
   - Validates responses against RFC 7591 schemas using Zod

2. **Protocol-Aware Validators**

   **RFC7591Validator** ([src/validation/rfc7591-validator.ts](src/validation/rfc7591-validator.ts))
   - Constructor accepts `ProtocolVersion` parameter
   - Enforces `private_key_jwt` JWKS requirements for 2025-11-25
   - Validates client metadata before registration
   - Checks redirect URI security (HTTPS, localhost, or custom schemes)
   - Verifies URI formats, email contacts, and timestamps

   **PKCEValidator** ([src/validation/pkce-validator.ts](src/validation/pkce-validator.ts))
   - Protocol-aware PKCE validation
   - Enforces S256 for MCP 2025-11-25
   - Allows S256 or plain for pre-2025-11-25

   **TokenValidator** ([src/validation/token-validator.ts](src/validation/token-validator.ts))
   - JWT access token validation
   - Strict audience validation for 2025-11-25
   - Optional audience validation for pre-2025-11-25

3. **Type Definitions**

   **Core Types** ([src/types/dcr.ts](src/types/dcr.ts))
   - Zod schemas for RFC 7591 data structures
   - ClientMetadata, RegistrationRequest, RegistrationResponse
   - ErrorResponse, ValidationResult

   **Protocol Version** ([src/types/protocol-version.ts](src/types/protocol-version.ts))
   - `ProtocolVersion` enum
   - `ProtocolConfig` interface with feature flags
   - `getProtocolConfig()` helper function

   **MCP 2025-11-25 Types**:
   - [src/types/client-id-metadata.ts](src/types/client-id-metadata.ts) - Client ID Metadata Documents
   - [src/types/token.ts](src/types/token.ts) - JWT access token claims
   - [src/types/oauth-discovery.ts](src/types/oauth-discovery.ts) - AS metadata

### MCP Integration

**IMPORTANT**: MCP is only used for discovery, not for DCR operations.

The client uses MCP for:
- RFC 9728 Protected Resource Metadata discovery (finding the authorization server)
- Only via WWW-Authenticate header or well-known endpoint
- **NOT for calling DCR tools** (DCR is not an MCP operation)

### DCR Integration

DCR operations are **direct HTTP requests**, not MCP:
- `registerClient()` - HTTP POST to registration endpoint
- `readClient()` - HTTP GET to registration client URI
- `updateClient()` - HTTP PUT to registration client URI
- `deleteClient()` - HTTP DELETE to registration client URI

### RFC 7591 Compliance

Key validation rules:
- `client_id` is required in responses
- `redirect_uris` required for authorization_code and implicit grants
- Redirect URIs must use HTTPS, localhost HTTP, or custom schemes
- Timestamps must be non-negative integers
- Email contacts must be valid
- URIs must be properly formed
- grant_types and response_types must be consistent

## Key Design Patterns

### Transport Layer
- **Stdio**: Only for local MCP servers (discovery only)
- **HTTP**: For remote servers (both discovery and DCR)

### DCR Pattern (NOT MCP Tools!)
DCR uses direct HTTP requests to OAuth endpoints:
```typescript
// ✅ CORRECT: Direct HTTP POST to OAuth endpoint
const response = await fetch(registrationEndpoint, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(metadata)
});

// ❌ WRONG: DCR is not an MCP tool
await client.callTool('register_client', metadata);
```

### Validation Flow
1. Validate client metadata before sending registration request
2. Send request to MCP server
3. Validate server response for RFC 7591 compliance
4. Report errors and warnings separately

### Error Handling
- Zod validation errors indicate schema violations
- DCRError indicates RFC 7591 error responses from the server
- Other errors indicate MCP transport or tool call failures

## Testing Strategy

### Compliance Test Modules

The compliance tester is organized into protocol-aware test modules:

**Core Tests (Both Protocols)**:
- **Protected Resource Metadata** ([src/compliance/compliance-tester.ts](src/compliance/compliance-tester.ts)) - RFC 9728
- **Authorization Server Discovery** - RFC 8414
- **Client Registration** ([src/compliance/client-registration-tests.ts](src/compliance/client-registration-tests.ts)) - Unified tests for all registration methods
- **OAuth Flow** - Authorization code with PKCE
- **JWT Validation** - RFC 9068 access token validation

**MCP 2025-11-25 Specific Tests**:
- **PKCE S256 Enforcement** ([src/compliance/pkce-tests.ts](src/compliance/pkce-tests.ts)) - Mandatory S256 validation
- **Resource Parameter** ([src/compliance/resource-parameter-tests.ts](src/compliance/resource-parameter-tests.ts)) - RFC 8707
- **Token Audience** ([src/compliance/token-audience-tests.ts](src/compliance/token-audience-tests.ts)) - Strict aud validation
- **Step-Up Authorization** ([src/compliance/step-up-auth-tests.ts](src/compliance/step-up-auth-tests.ts)) - insufficient_scope handling
- **Private Key JWT** ([src/compliance/private-key-jwt-tests.ts](src/compliance/private-key-jwt-tests.ts)) - Advanced authentication
- **Server Capabilities Discovery** ([src/compliance/server-capabilities-tests.ts](src/compliance/server-capabilities-tests.ts)) - End-to-end authentication verification

### Test Metadata System

Test metadata ([src/compliance/test-metadata.ts](src/compliance/test-metadata.ts)) provides:
- RFC references and URLs for each test
- Expected outcomes
- Remediation guidance when tests fail
- Integration with compliance reporting

### Unit Tests

Unit tests in [src/tests/validator.test.ts](src/tests/validator.test.ts) cover:
- Valid and invalid registration responses
- Metadata validation edge cases
- Redirect URI security validation
- Grant type consistency checks
- URI and email format validation

Use Vitest for unit tests with coverage reporting.

## Development Guidance

### Working with Protocol Versions

When adding new features or modifying existing code, follow these guidelines:

#### 1. Creating Protocol-Aware Validators

```typescript
export class MyValidator {
  private protocolVersion: ProtocolVersion;

  constructor(protocolVersion: ProtocolVersion = ProtocolVersion.PRE_2025_11_25) {
    this.protocolVersion = protocolVersion;
  }

  validate(data: SomeData): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Common validation (both protocols)
    if (!data.requiredField) {
      errors.push('Missing required field');
    }

    // Protocol-specific validation
    if (this.protocolVersion === ProtocolVersion.MCP_2025_11_25) {
      // Stricter validation for 2025-11-25
      if (!data.newRequirement) {
        errors.push('New requirement missing for MCP 2025-11-25');
      }
    }

    return { compliant: errors.length === 0, errors, warnings };
  }
}
```

#### 2. Creating Protocol-Aware Tests

```typescript
export async function runMyTests(
  config: ServerTestConfig,
  ...additionalParams
): Promise<ComplianceTestResult[]> {
  const results: ComplianceTestResult[] = [];
  const protocolVersion = config.protocolVersion || ProtocolVersion.PRE_2025_11_25;

  // Only run for MCP 2025-11-25
  if (protocolVersion !== ProtocolVersion.MCP_2025_11_25) {
    results.push({
      id: 'my-1.0',
      category: ComplianceCategory.MY_CATEGORY,
      requirement: 'My feature support',
      status: 'skip',
      message: 'This feature is only tested for MCP 2025-11-25',
      timestamp: new Date()
    });
    return results;
  }

  // Run tests...
  return results;
}
```

#### 3. Maintaining Backward Compatibility

**DO**:
- ✅ Default to `ProtocolVersion.PRE_2025_11_25` for backward compatibility
- ✅ Make 2025-11-25 features opt-in via protocol version
- ✅ Preserve existing test behavior for pre-2025-11-25
- ✅ Document protocol-specific behavior clearly

**DON'T**:
- ❌ Break existing pre-2025-11-25 tests
- ❌ Make 2025-11-25 features required for all protocols
- ❌ Change default behavior without protocol version check

#### 4. Test ID Naming Convention

Follow this pattern for test IDs:

**Format**: `<category-prefix>-<method>-<number>`

**Examples**:
- `cr-pre-1.0` - Client Registration, Preregistration method, test 1.0
- `cr-cidm-2.0` - Client Registration, Client ID Metadata Document, test 2.0
- `cr-dcr-3.0` - Client Registration, DCR method, test 3.0
- `pkce-2.0` - PKCE category, test 2.0
- `step-1.5` - Step-up authorization, test 1.5 (scope challenge)

#### 5. Adding Test Metadata

For each test, add metadata to [src/compliance/test-metadata.ts](src/compliance/test-metadata.ts):

```typescript
'my-1.0': {
  rfcReference: 'MCP 2025-11-25 Section X.Y',
  rfcUrl: 'https://modelcontextprotocol.io/specification/2025-11-25/...',
  expected: 'Clear description of what should happen',
  remediation: 'Step-by-step guidance on how to fix failures'
}
```

### Common Patterns

#### Checking Protocol Version

```typescript
// In validators
if (this.protocolVersion === ProtocolVersion.MCP_2025_11_25) {
  // Enforce stricter rules
}

// In tests
const protocolVersion = config.protocolVersion || ProtocolVersion.PRE_2025_11_25;
if (protocolVersion === ProtocolVersion.MCP_2025_11_25) {
  // Run 2025-11-25 specific tests
}
```

#### Feature Flags

```typescript
const protocolConfig = getProtocolConfig(protocolVersion);

if (protocolConfig.enforceS256PKCE) {
  // Enforce S256
}

if (protocolConfig.requireResourceParameter) {
  // Require resource parameter
}
```

### Best Practices

1. **Always document protocol-specific behavior** in code comments
2. **Use test metadata** for every test to provide context and remediation
3. **Test both protocol versions** during development
4. **Keep validators focused** - one validator per concern
5. **Use descriptive test IDs** that indicate protocol version when relevant

## Configuration

### Environment Variables
- `INITIAL_ACCESS_TOKEN`: Optional initial access token for server authentication

### Server Configuration
Configure the MCP server in `DCRClientConfig`:
```typescript
{
  serverCommand: 'node',
  serverArgs: ['path/to/mcp-server.js'],
  registrationEndpoint: 'https://server.com/register',
  initialAccessToken: process.env.INITIAL_ACCESS_TOKEN
}
```

## MCP Server Requirements

For this client to work, the MCP server only needs to:
1. Implement RFC 9728 (Protected Resource Metadata)
2. Advertise its authorization server via `authorization_servers` field
3. Either via `WWW-Authenticate` header or `/.well-known/oauth-protected-resource`

**That's it!** The MCP server does NOT need to:
- ❌ Implement DCR endpoints
- ❌ Expose DCR as MCP tools
- ❌ Handle registration requests

## OAuth Server Requirements

The authorization server (discovered from MCP) must:
1. Implement RFC 8414 (OAuth Discovery) at `/.well-known/oauth-authorization-server`
2. Implement RFC 7591 (DCR) at the `registration_endpoint`
3. Optionally implement RFC 7592 (Client Management)

## RFC 7591 References

- Client Registration: Section 3.1
- Registration Response: Section 3.2.1
- Error Responses: Section 3.2.2
- Metadata Fields: Section 2
- Security: Section 5
