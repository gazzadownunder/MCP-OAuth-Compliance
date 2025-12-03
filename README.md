# MCP OAuth Compliance Tester

Web-based tool for testing MCP server OAuth compliance with RFC 9728, RFC 8414, RFC 7591, RFC 9068, RFC 7519, RFC 7515, OAuth 2.1, and **MCP 2025-11-25 specification**.

✨ **NEW**: Now supports both Pre-2025-11-25 and **MCP 2025-11-25** protocol versions!

**GitHub Repository**: https://github.com/gazzadownunder/MCP-OAuth-Compliance

## Quick Start

```bash
npm install
npm start
```

Open `http://localhost:3456` in your browser.

### Global Installation (CLI)

Install globally to use as a command-line tool:

```bash
npm install -g .
mcp-oauth-compliance
```

Or install directly from GitHub:

```bash
npm install -g github:gazzadownunder/mcp-oauth-compliance
mcp-oauth-compliance
```

Or run directly via npx:

```bash
npx github:gazzadownunder/mcp-oauth-compliance
```

### CLI Options

```bash
mcp-oauth-compliance [options]

Options:
  -p, --port <number>  Server port (default: 3001, or PORT env var)
  -h, --help           Show help message
```

Examples:
```bash
mcp-oauth-compliance --port 3000
mcp-oauth-compliance -p 9000
PORT=4000 mcp-oauth-compliance
```

## Protocol Version Support

This compliance tester supports both the legacy and updated MCP authorization protocols:

### Pre-2025-11-25 (Original MCP OAuth)
The original MCP OAuth specification supporting standard DCR and OAuth flows.

**Supported Features:**
- RFC 7591 Dynamic Client Registration (DCR)
- Optional PKCE (S256 or plain methods)
- Standard OAuth 2.0/2.1 authorization flows
- JWT access token validation
- Client registration via DCR or preregistration

### MCP 2025-11-25 (Enhanced Security) 🆕
Enhanced specification with improved security and new capabilities.

**New Requirements:**
- ✅ **S256 PKCE (REQUIRED)**: Mandatory S256 code challenge method, plain discouraged
- ✅ **Client ID Metadata Documents**: HTTPS URLs as client identifiers with hosted metadata
- ✅ **Resource Parameter (RFC 8707)**: Resource indicators in authorization/token requests
- ✅ **Token Audience Validation**: Strict JWT `aud` claim verification
- ✅ **Step-Up Authorization**: Handle `insufficient_scope` with re-authorization flow
- ✅ **Private Key JWT**: Enhanced client authentication option

**Client Registration Priority (MCP 2025-11-25):**
1. **Preregistration** (Priority 1) - Use existing client credentials when available
2. **Client ID Metadata Document** (Priority 2) - HTTPS URL as client_id
3. **Dynamic Client Registration** (Priority 3) - RFC 7591 fallback

### Selecting Protocol Version

In the web interface, select your desired protocol version from the dropdown:

1. **Pre-2025-11-25**: Test servers using the original specification
2. **MCP 2025-11-25**: Test servers implementing the latest specification

The tester automatically adjusts validation rules and test coverage based on your selection.

## Features

### Core Features
- **Web Interface**: Interactive compliance testing dashboard with collapsible test sections
- **Dual Protocol Support**: Test against Pre-2025-11-25 OR MCP 2025-11-25 specifications
- **Comprehensive Tests**: RFC 9728 (Protected Resource Metadata), RFC 8414 (AS Discovery), RFC 7591 (DCR), OAuth 2.1
- **HTTPS Validation**: Transport security checks per OAuth requirements
- **Multiple Discovery Methods**: Standard RFC 8414 + OIDC discovery
- **Pre-configured Client Mode**: Test with existing OAuth clients (bypasses DCR)
- **Interactive OAuth Flow**: Browser-based authorization with PKCE
- **Smart Port Selection**: Automatically avoids the server's port and finds available callback port (up to 20 attempts)
- **Enhanced Debug Mode**: Full HTTP request/response capture with expandable UI sections for troubleshooting
- **RFC 7592 Validation**: Validates `registration_client_uri` format with auto-correction for relative URLs
- **Persistent UI State**: Section collapse/expand preferences saved across test runs using localStorage

## Configuration Options

| Option | Description | Protocol |
|--------|-------------|----------|
| **Protocol Version** | Select Pre-2025-11-25 or MCP 2025-11-25 | Both |
| **Skip DCR Tests** | Bypass Dynamic Client Registration testing | Both |
| **Skip OAuth Flow** | Skip token acquisition tests | Both |
| **Interactive Auth** | Enable browser-based OAuth flow | Both |
| **Pre-configured Client** | Use existing client credentials instead of DCR | Both |
| **Callback Port** | Port for OAuth callback (default: 3000). Automatically finds next available port | Both |
| **Redirect URI** | Full redirect URI registered with your IDP | Both |
| **Resource URI** | Resource indicator for RFC 8707 (REQUIRED for 2025-11-25) | Both |
| **Privileged Tool Name** | Tool name for scope challenge test (optional, for step-1.5) | 2025-11-25 |
| **Client ID Metadata URL** | HTTPS URL for Client ID Metadata Document | 2025-11-25 |
| **Client ID/Secret** | Pre-configured client credentials | Both |
| **Scope** | OAuth scopes to request | Both |
| **Enable Debug** | Capture and display HTTP request/response data for all server interactions | Both |

## Test Categories

### Pre-2025-11-25 Protocol

#### 1. Protected Resource Metadata (RFC 9728)
- HTTPS transport validation
- Well-known endpoint discovery
- WWW-Authenticate header parsing
- Authorization server reference validation

#### 2. Authorization Server Discovery (RFC 8414)
- HTTPS transport validation
- Standard and OIDC discovery
- Required endpoint validation
- PKCE support detection

#### 3. Client Registration
- **Preregistration**: Validate existing client credentials
- **Dynamic Client Registration (RFC 7591/7592)**: Client registration with various grant types
  - Response validation (HTTP 201, client_id, etc.)
  - Client management URI validation (RFC 7592)
  - Auto-correction for servers returning relative URLs

#### 4. OAuth 2.1 Flow
- PKCE requirement (S256 or plain)
- Authorization code flow
- Token exchange validation

#### 5. JWT Access Token Validation (RFC 9068)
- Token structure and encoding
- Required claims (iss, sub, exp, iat)
- Issuer validation against AS metadata
- JWKS endpoint and key verification

#### 6. Protected Resource Access
- Bearer token authentication
- Access token validation

### MCP 2025-11-25 Protocol (Additional Tests) 🆕

#### 7. PKCE S256 Enforcement
- S256 method required (not optional)
- Plain method discouraged warning
- Code challenge validation

#### 8. Resource Parameter (RFC 8707)
- Resource parameter in authorization request
- Resource parameter in token request
- Resource validation in token response
- JWT resource claim validation

#### 9. Token Audience Validation
- JWT `aud` claim presence
- Audience matches resource parameter
- Multi-audience support
- Prevents token passthrough attacks

#### 10. Step-Up Authorization
- Insufficient scope error detection
- Required scope parsing from error response
- Re-authorization with elevated scopes
- Retry limit enforcement
- **Scope challenge test (optional)**: Tests complete flow with privileged tool

#### 11. Private Key JWT Authentication
- JWKS configuration validation
- JWT assertion creation
- Token endpoint authentication
- Signature verification

## Documentation

- [COMPLIANCE-TESTER.md](https://github.com/gazzadownunder/MCP-OAuth-Compliance/blob/master/COMPLIANCE-TESTER.md) - Detailed test documentation
- [CLAUDE.md](https://github.com/gazzadownunder/MCP-OAuth-Compliance/blob/master/CLAUDE.md) - Development guide

## Development

```bash
npm run build        # Compile TypeScript
npm test             # Run unit tests
npm run lint         # Check code style
npm run type-check   # Type validation
```

### TLS Version Support

The compliance tester supports modern TLS protocols for secure HTTPS connections:
- **TLS 1.3** ✅ (Preferred - Latest and most secure)
- **TLS 1.2** ✅ (Minimum supported version)
- **TLS 1.1 and below** ❌ (Not supported for security reasons)

Powered by Node.js v22.14.0 with OpenSSL 3.0.15+quic.

### Certificate Handling

**The compliance tester allows self-signed certificates by default** to facilitate testing and development. Certificate warnings are automatically tracked and displayed in the test results with remediation recommendations.

**Certificate Warnings Tracked:**
- ⚠️ Self-signed certificates
- ⚠️ Expired certificates
- ⚠️ Not-yet-valid certificates
- ⚠️ Hostname mismatches
- ⚠️ Untrusted CA chains

All warnings include:
- Certificate details (issuer, subject, validity dates)
- Clear description of the issue
- Recommended actions for resolution

### Environment Variables

- **`DEBUG_CERTS`**: Enable detailed certificate verification debugging for HTTPS requests
  - Set to `true` or `1` to enable
  - Displays certificate details (subject, issuer, validity dates, fingerprint, TLS version)
  - Shows detailed error messages for common certificate issues
  - Provides remediation suggestions for certificate problems
  - Example: `DEBUG_CERTS=true npm start`

- **`NODE_TLS_REJECT_UNAUTHORIZED`**: Enforce strict TLS certificate validation
  - Default: `0` (allows self-signed certificates with warnings)
  - Set to `1` to enforce strict certificate validation (will reject self-signed certificates)
  - Example: `NODE_TLS_REJECT_UNAUTHORIZED=1 npm start`

## Project Structure

- [`src/compliance/`](https://github.com/gazzadownunder/MCP-OAuth-Compliance/tree/master/src/compliance) - Compliance tester implementation
- [`src/client/`](https://github.com/gazzadownunder/MCP-OAuth-Compliance/tree/master/src/client) - DCR client library
- [`src/validation/`](https://github.com/gazzadownunder/MCP-OAuth-Compliance/tree/master/src/validation) - RFC 7591 validators
- [`src/types/`](https://github.com/gazzadownunder/MCP-OAuth-Compliance/tree/master/src/types) - TypeScript definitions
- [`public/`](https://github.com/gazzadownunder/MCP-OAuth-Compliance/tree/master/public) - Web interface
