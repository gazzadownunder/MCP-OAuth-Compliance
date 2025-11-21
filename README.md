# MCP OAuth Compliance Tester

Web-based tool for testing MCP server OAuth compliance with RFC 9728, RFC 8414, RFC 7591, RFC 9068, RFC 7519, RFC 7515, and OAuth 2.1.

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

## Features

- **Web Interface**: Interactive compliance testing dashboard
- **Comprehensive Tests**: RFC 9728 (Protected Resource Metadata), RFC 8414 (AS Discovery), RFC 7591 (DCR), OAuth 2.1
- **HTTPS Validation**: Transport security checks per OAuth requirements
- **Multiple Discovery Methods**: Standard RFC 8414 + Keycloak-style discovery
- **Pre-configured Client Mode**: Test with existing OAuth clients (bypasses DCR)
- **Interactive OAuth Flow**: Browser-based authorization with PKCE

## Configuration Options

| Option | Description |
|--------|-------------|
| **Skip DCR Tests** | Bypass Dynamic Client Registration testing |
| **Skip OAuth Flow** | Skip token acquisition tests |
| **Interactive Auth** | Enable browser-based OAuth flow |
| **Pre-configured Client** | Use existing client credentials instead of DCR |
| **Callback Port** | Port for OAuth callback (default: 3000) |
| **Redirect URI** | Full redirect URI registered with your IDP |
| **Resource URI** | Resource indicator for RFC 8707 |
| **Client ID/Secret** | Pre-configured client credentials |
| **Scope** | OAuth scopes to request |

## Test Categories

### 1. Protected Resource Metadata (RFC 9728)
- HTTPS transport validation
- Well-known endpoint discovery
- WWW-Authenticate header parsing
- Authorization server reference validation

### 2. Authorization Server Discovery (RFC 8414)
- HTTPS transport validation
- Standard and Keycloak-style discovery
- Required endpoint validation
- PKCE support detection

### 3. Dynamic Client Registration (RFC 7591)
- Client registration with various grant types
- Response validation
- Client management (RFC 7592)

### 4. OAuth 2.1 Compliance
- PKCE requirement (S256)
- Token exchange validation
- Resource indicator support (RFC 8707)

### 5. JWT Access Token Validation (RFC 9068)
- Token structure and encoding
- Required claims (iss, sub, exp, iat)
- Issuer validation against AS metadata
- JWKS endpoint and key verification

## Documentation

- [COMPLIANCE-TESTER.md](COMPLIANCE-TESTER.md) - Detailed test documentation
- [CLAUDE.md](CLAUDE.md) - Development guide

## Development

```bash
npm run build        # Compile TypeScript
npm test             # Run unit tests
npm run lint         # Check code style
npm run type-check   # Type validation
```

## Project Structure

- `src/compliance/` - Compliance tester implementation
- `src/client/` - DCR client library
- `src/validation/` - RFC 7591 validators
- `src/types/` - TypeScript definitions
- `public/` - Web interface
