# MCP Authorization Flow Compliance Tester

A web-based tool to test MCP server compliance with the OAuth 2.1 authorization flow, including:
- **RFC 9728**: OAuth 2.0 Protected Resource Metadata
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata
- **RFC 7591**: OAuth 2.0 Dynamic Client Registration
- **RFC 6749**: OAuth 2.0 Authorization Framework
- **OAuth 2.1**: Authorization Code Flow with PKCE
- **RFC 8707**: Resource Indicators for OAuth 2.0

## Features

- **Comprehensive Testing**: Tests all aspects of the MCP authorization flow
- **Web Interface**: Modern dark-themed UI with collapsible options panel
- **Toggle Switches**: Clean on/off slider controls for test options
- **CORS Handling**: Backend proxy overcomes browser CORS restrictions
- **Visual Results**: Clear pass/fail/warning indicators with detailed error messages
- **Hierarchical Display**: Indented test results showing logical groupings
- **Interactive OAuth**: Complete browser-based authorization code flow testing
- **Pre-Configured Client**: Option to bypass DCR with your own client_id

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Run the Compliance Tester

```bash
npm run compliance-tester
```

This will:
1. Start the backend API server on port 3001
2. Automatically open your default browser
3. Display the compliance testing interface

### 3. Test Your Server

1. Enter your MCP server URL (e.g., `https://api.example.com/public/mcp`)
2. Click "Options" to expand and configure test settings
3. Click "Run Compliance Tests"
4. View detailed results with pass/fail/warning indicators

## Test Options

The options panel provides toggle switches for each setting:

| Option | Description |
|--------|-------------|
| **Skip DCR Tests** | Bypass Dynamic Client Registration testing |
| **Skip OAuth Flow Tests** | Bypass OAuth authorization flow testing |
| **Interactive OAuth Flow** | Enable browser-based user authentication (opens browser for IDP login) |
| **Use Pre-Configured Client** | Provide your own client_id instead of using DCR |

### Interactive OAuth Flow Options

When enabled, additional fields appear:
- **OAuth Callback Port**: Port for callback server (default: 3000)
- **Resource URI (RFC 8707)**: Optional resource indicator for audience restriction

### Pre-Configured Client Options

When enabled, additional fields appear:
- **Client ID**: Your pre-registered client_id (required)
- **Client Secret**: Optional client secret for confidential clients
- **OAuth Scopes**: Space-separated scopes (optional - server uses defaults if not specified)

## Complete Test Reference

### 1. Protected Resource Metadata Discovery (RFC 9728)

| Test ID | Requirement | RFC Reference | Status |
|---------|-------------|---------------|--------|
| prm-1.0 | HTTPS transport required (except localhost) | RFC 6749 §3.1 | REQUIRED |
| prm-1.1 | HTTP 401 response when unauthorized | RFC 9728 §2 | REQUIRED |
| prm-1.2 | WWW-Authenticate header present | RFC 9728 §2 | REQUIRED |
| prm-1.3 | `resource_metadata` parameter in WWW-Authenticate | RFC 9728 §2.1 | RECOMMENDED |

**MCP 4.2.1: Explicit Discovery**

| Test ID | Requirement | RFC Reference | Status |
|---------|-------------|---------------|--------|
| prm-1.4 | PRM accessible at resource_metadata URI | MCP 4.2.1 / RFC 9728 §2.1 | REQUIRED (if provided) |

**MCP 4.2.2: Fallback Discovery** (passes if any path succeeds)

| Test ID | Requirement | RFC Reference | Status |
|---------|-------------|---------------|--------|
| prm-1.5 | Path A: Path-specific well-known URI | MCP 4.2.2 | WARNING if fails |
| prm-1.6 | Path B: Standard well-known URI | MCP 4.2.2 / RFC 9728 §3 | WARNING if fails |
| prm-1.7 | Path C: OAuth AS well-known URI (fallback) | RFC 8414 §3 | WARNING if fails |

**PRM Content Validation**

| Test ID | Requirement | RFC Reference | Status |
|---------|-------------|---------------|--------|
| prm-1.8 | PRM contains `authorization_servers` array | RFC 9728 §3 | REQUIRED (warning if AS found via fallback) |
| prm-1.9 | PRM contains `scopes_supported` | RFC 9728 §3 | RECOMMENDED |

### 2. Authorization Server Discovery (RFC 8414)

| Test ID | Requirement | RFC Reference | Status |
|---------|-------------|---------------|--------|
| as-2.0a | HTTPS transport required for AS (except localhost) | RFC 6749 §3.1, RFC 8414 §2 | REQUIRED |
| as-2.0b | AS URL has no trailing slash | RFC 8414 §3 | WARNING |
| as-2.1 | AS metadata endpoint accessible | RFC 8414 §3 | REQUIRED |
| as-2.2 | `registration_endpoint` present | RFC 8414 §2 | OPTIONAL |
| as-2.2-https | registration_endpoint uses HTTPS | RFC 6749 §3.1 | REQUIRED (if present) |
| as-2.3 | `authorization_endpoint` present | RFC 8414 §2 | REQUIRED |
| as-2.3-https | authorization_endpoint uses HTTPS | RFC 6749 §3.1 | REQUIRED |
| as-2.4 | `token_endpoint` present | RFC 8414 §2 | REQUIRED |
| as-2.4-https | token_endpoint uses HTTPS | RFC 6749 §3.1 | REQUIRED |
| as-2.5 | `scopes_supported` present | RFC 8414 §2 | OPTIONAL |

**AS Metadata Discovery Methods** (tries in order):
1. Direct URL (if AS URL itself returns metadata)
2. RFC 8414 standard: `{origin}/.well-known/oauth-authorization-server{path}`
3. Keycloak-style: `{issuer}/.well-known/oauth-authorization-server`

### 3. Dynamic Client Registration (RFC 7591)

| Test ID | Requirement | RFC Reference | Status |
|---------|-------------|---------------|--------|
| dcr-3.1 | Registration endpoint accepts POST | RFC 7591 §3 | REQUIRED |
| dcr-3.2 | Returns HTTP 201 on success | RFC 7591 §3.2.1 | REQUIRED |
| dcr-3.2a | Accepts registration with `refresh_token` grant (fallback) | RFC 7591 §2 | WARNING |
| dcr-3.3 | Response contains `client_id` | RFC 7591 §3.2.1 | REQUIRED |
| dcr-3.4 | `client_secret_expires_at` present when `client_secret` issued | RFC 7591 §3.2.1 | REQUIRED |
| dcr-3.5 | Supports PKCE (`token_endpoint_auth_method: "none"`) | RFC 7591 §2 | REQUIRED |

**DCR Registration Fields Sent:**
- `client_name`: "MCP Compliance Tester"
- `redirect_uris`: `["http://localhost:{callbackPort}/callback"]`
- `grant_types`: `["authorization_code"]` (fallback adds `"refresh_token"`)
- `response_types`: `["code"]`
- `token_endpoint_auth_method`: `"none"`
- `scope`: Only included if explicitly configured by user

### 4. OAuth 2.1 + PKCE Flow

**Metadata Tests** (always run)

| Test ID | Requirement | RFC Reference | Status |
|---------|-------------|---------------|--------|
| oauth-4.1 | Supports `authorization_code` grant type | RFC 6749 §4.1 | REQUIRED |
| oauth-4.2 | Supports PKCE with S256 | RFC 7636 §4.2 | REQUIRED |

**Interactive Flow Tests** (requires `interactiveAuth` enabled)

| Test ID | Requirement | RFC Reference | Status |
|---------|-------------|---------------|--------|
| oauth-4.3 | Authorization endpoint accepts requests | RFC 6749 §3.1 | REQUIRED |
| oauth-4.4 | State parameter returned unchanged (CSRF protection) | RFC 6749 §10.12 | REQUIRED |
| oauth-4.5 | Token endpoint accepts authorization_code with PKCE | RFC 6749 §4.1.3, RFC 7636 | REQUIRED |
| oauth-4.6 | Issues `access_token` | RFC 6749 §5.1 | REQUIRED |
| oauth-4.7 | Issues Bearer `token_type` | RFC 6750 §1 | REQUIRED |
| oauth-4.8 | Includes `expires_in` | RFC 6749 §5.1 | RECOMMENDED |
| oauth-4.9 | Issues `refresh_token` | RFC 6749 §5.1 | OPTIONAL |
| oauth-4.10 | Supports resource parameter (RFC 8707) | RFC 8707 | OPTIONAL |

**Scope Handling in OAuth Flow:**
- If scope configured by user: Uses configured scope
- If scope returned from DCR registration: Uses registered scope
- Otherwise: No scope sent (server uses its defaults)

### 5. JWT Access Token Validation (RFC 9068)

| Test ID | Requirement | RFC Reference | Status |
|---------|-------------|---------------|--------|
| jwt-5.1 | Access token is a JWT (three Base64URL parts) | RFC 7519 §3 | WARNING if opaque |
| jwt-5.2 | JWT is properly Base64URL-encoded | RFC 7519 §3 | REQUIRED |
| jwt-5.3 | JWT header contains "alg" claim (not "none") | RFC 7515 §4.1.1 | REQUIRED |
| jwt-5.4 | JWT header contains "kid" for key identification | RFC 7515 §4.1.4 | OPTIONAL |
| jwt-5.5 | JWT contains required claims (iss, sub, exp, iat) | RFC 9068 §2.2 | REQUIRED |
| jwt-5.6 | JWT issuer (iss) matches authorization server | RFC 9068 §2.2 | REQUIRED |
| jwt-5.7 | JWT is not expired (exp claim) | RFC 7519 §4.1.4 | REQUIRED |
| jwt-5.8 | JWT issued-at (iat) is not in the future | RFC 7519 §4.1.6 | REQUIRED |
| jwt-5.9 | JWKS URI available in AS metadata | RFC 8414 §2 | OPTIONAL |
| jwt-5.10 | JWKS contains signing keys | RFC 7517 | REQUIRED (if JWKS available) |
| jwt-5.11 | JWKS contains key matching token "kid" | RFC 7517 | REQUIRED (if kid present) |
| jwt-5.12 | Key algorithm matches token algorithm | RFC 7515 | REQUIRED (if key found) |
| jwt-5.13 | JWT contains audience (aud) claim | RFC 9068 §2.2 | OPTIONAL |
| jwt-5.14 | JWT signature is cryptographically valid | RFC 7515 §5.2 | REQUIRED |

**JWT Validation runs automatically after successful token exchange.**

## Test Result Types

| Icon | Status | Description |
|------|--------|-------------|
| ✅ | **Pass** | Server is compliant with the standard |
| ❌ | **Fail** | Server does not meet RFC requirements |
| ⚠️ | **Warning** | Server works but may not be fully RFC compliant |
| ⊘ | **Skip** | Test skipped due to missing dependencies or configuration |

### Warning Examples
- HTTP used on localhost (acceptable for development only)
- PRM not found but AS discovered via fallback (tests continue)
- Server requires `refresh_token` grant (stricter than RFC 7591)
- AS URL has trailing slash (violates RFC 8414)

## Hierarchical Test Display

Tests are organized hierarchically with indentation:

```
✅ HTTPS transport required for production
✅ HTTP 401 response when unauthorized
✅ WWW-Authenticate header present
✅ MCP 4.2.2: Fallback Discovery (1 of 3 paths worked)
    ⚠️ Path A: Path-specific well-known URI
    ⚠️ Path B: Standard well-known URI
    ✅ Path C: OAuth AS well-known URI
⚠️ PRM contains authorization_servers (AS found via fallback)
```

## Architecture

### Backend Service ([src/server/api-server.ts](src/server/api-server.ts))

- Express.js server with CORS enabled
- Proxies requests to MCP servers to avoid CORS issues
- Provides REST API for running tests
- Serves static frontend files

### Compliance Tester ([src/compliance/compliance-tester.ts](src/compliance/compliance-tester.ts))

- Core testing logic
- Implements all RFC compliance checks
- Returns structured test results
- Handles PKCE generation and OAuth callback flow

### Frontend ([public/index.html](public/index.html))

- Dark-themed modern web interface
- Collapsible "Options" panel with expand arrow
- Toggle switches (sliders) on left side of option text
- Real-time test results display
- Expandable details with RFC references and remediation guidance

## API Endpoints

### `POST /api/test/sync`

Run compliance tests synchronously.

**Request Body:**
```json
{
  "serverUrl": "https://api.example.com/public/mcp",
  "skipDCR": false,
  "skipOAuthFlow": false,
  "interactiveAuth": false,
  "usePreConfiguredClient": false,
  "clientId": "my-client-id",
  "clientSecret": "optional-secret",
  "scope": "openid profile",
  "callbackPort": 3000,
  "resourceUri": "https://api.example.com",
  "timeout": 30000
}
```

**Response:**
```json
{
  "serverUrl": "https://api.example.com/public/mcp",
  "startTime": "2025-01-20T10:00:00.000Z",
  "endTime": "2025-01-20T10:00:30.000Z",
  "results": [
    {
      "id": "prm-1.0",
      "category": "1. Protected Resource Metadata (RFC 9728)",
      "requirement": "HTTPS transport required for production (REQUIRED)",
      "status": "pass",
      "message": "Server is using HTTPS protocol",
      "rfcReference": "RFC 6749 Section 3.1",
      "rfcUrl": "https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1",
      "timestamp": "2025-01-20T10:00:01.000Z"
    }
  ],
  "summary": {
    "total": 25,
    "passed": 18,
    "failed": 2,
    "skipped": 3,
    "warnings": 2
  }
}
```

### `POST /api/test/rerun/:testId`

Rerun a single test by its ID.

### `GET /api/health`

Health check endpoint.

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `serverUrl` | string | required | MCP server URL to test |
| `skipDCR` | boolean | false | Skip DCR tests |
| `skipOAuthFlow` | boolean | false | Skip OAuth flow tests |
| `interactiveAuth` | boolean | false | Enable interactive OAuth flow |
| `usePreConfiguredClient` | boolean | false | Use provided client_id instead of DCR |
| `clientId` | string | - | Pre-configured client ID |
| `clientSecret` | string | - | Pre-configured client secret |
| `scope` | string | - | OAuth scopes (space-separated) |
| `callbackPort` | number | 3000 | OAuth callback server port |
| `resourceUri` | string | - | RFC 8707 resource indicator |
| `timeout` | number | 30000 | Request timeout (ms) |

## Troubleshooting

### HTTPS Warnings on Localhost

HTTP is acceptable for localhost development. The tester shows a warning but allows tests to continue.

### Invalid Scope Error

If you see `invalid_scope` errors:
1. The OAuth flow was requesting scopes not registered with the client
2. Either configure matching scopes in the UI, or
3. Leave scope empty to let the server use its defaults

### DCR Fallback Test

The fallback test adds `refresh_token` to grant_types. Some servers require this even though RFC 7591 doesn't mandate it.

### Browser Doesn't Open for OAuth

On Windows, the tester uses `start ""` command with empty title to open URLs correctly. If browser doesn't open:
- Check if the callback port is available
- Verify browser isn't blocking popups
- Copy the URL from console output manually

### AS Metadata Not Found

The tester tries three discovery methods:
1. Direct URL (if AS URL returns metadata directly)
2. RFC 8414 standard: well-known inserted between host and path
3. Keycloak-style: well-known appended to issuer path

Check server logs to see which URL was requested.

## Server Requirements Summary

For full compliance (no warnings):

### Transport Security
1. **Use HTTPS** for all production endpoints
2. HTTP only acceptable for localhost/development

### Protected Resource (RFC 9728)
3. Return **HTTP 401** for unauthorized requests
4. Include **WWW-Authenticate** header with `resource_metadata` parameter
5. Host PRM at `/.well-known/oauth-protected-resource`
6. Include **`authorization_servers`** array in PRM

### Authorization Server (RFC 8414)
7. Host AS metadata at well-known URI
8. **No trailing slash** on issuer URL
9. Include required endpoints: `authorization_endpoint`, `token_endpoint`
10. Advertise PKCE: `code_challenge_methods_supported: ["S256"]`

### Dynamic Client Registration (RFC 7591)
11. Accept registration with only `authorization_code` grant
12. Return **HTTP 201** (not 200) on success
13. Include `client_id` in response
14. Include `client_secret_expires_at` when issuing secrets

### OAuth 2.1 + PKCE
15. Validate PKCE code_challenge and code_verifier
16. Return **state parameter unchanged**
17. Issue **Bearer** access tokens
18. Support RFC 8707 resource parameter (optional)

## Recent Changes

### JWT Access Token Validation (jwt-5.x)
- Added complete JWT validation test category
- Validates token structure, claims, expiration
- Fetches JWKS and verifies key availability
- **Full cryptographic signature verification** using jose library
- Optional fields (kid, jwks_uri, aud) show as skip when missing

### HTTPS Transport Tests (prm-1.0, as-2.0a, as-2.x-https)
- Added as first test in each category
- Fails for non-localhost HTTP URLs
- Warns for localhost HTTP (acceptable for development)
- Checks all endpoint URLs individually

### Scope Handling
- DCR no longer sends scope by default (some servers reject it)
- OAuth flow uses: configured scope → DCR-returned scope → no scope
- Prevents `invalid_scope` errors from scope mismatches

### AS Metadata Discovery
- Added Keycloak-style discovery method
- Tries: direct URL → RFC 8414 standard → appended to path

### Callback Port
- DCR registration now uses configured callback port
- Ensures redirect_uri matches between DCR and OAuth flow

### UI Improvements
- Collapsible "Options" panel with expand arrow (▶/▼)
- Toggle switches (sliders) instead of checkboxes
- Switches positioned on left side of option text
- Smooth expand/collapse animations
- Pre-configured client option with expandable fields

### Browser Launch Fix (Windows)
- Fixed `start` command with empty title for proper URL opening

### Fallback Discovery (MCP 4.2.2)
- Individual path failures show as warnings (not failures)
- Overall test passes if any path succeeds

## Related Documentation

- [CLAUDE.md](CLAUDE.md) - Project overview and development guide

## License

MIT
