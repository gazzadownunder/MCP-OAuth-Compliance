# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DCR-Client tests Dynamic Client Registration (DCR) compliance with RFC 7591.

**IMPORTANT**: DCR is NOT part of MCP. This client uses MCP only for discovery (RFC 9728). The actual DCR operations are pure OAuth/HTTP requests.

### How It Works

1. **Discovery via MCP** (RFC 9728): MCP server advertises its authorization server
2. **OAuth Discovery** (RFC 8414): Authorization server advertises registration endpoint
3. **DCR Operations** (RFC 7591/7592): Direct HTTP requests to OAuth endpoints

## Development Commands

### Setup
```bash
npm install
```

### Development
```bash
npm start                # Run the compliance tester web interface
npm run type-check       # Type check without emitting files
```

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

## Architecture

### Core Components

1. **DCRClient** ([src/client/dcr-client.ts](src/client/dcr-client.ts))
   - Main client class for interacting with MCP servers
   - Manages connection lifecycle via MCP SDK's StdioClientTransport
   - Implements RFC 7591 operations: register, read, update, delete
   - Calls MCP tools on the server to perform DCR operations
   - Validates responses against RFC 7591 schemas using Zod

2. **RFC7591Validator** ([src/validation/rfc7591-validator.ts](src/validation/rfc7591-validator.ts))
   - Validates client metadata before registration
   - Validates server responses for RFC 7591 compliance
   - Checks redirect URI security (HTTPS, localhost, or custom schemes)
   - Validates grant_types and response_types consistency
   - Verifies URI formats, email contacts, and timestamps

3. **Type Definitions** ([src/types/dcr.ts](src/types/dcr.ts))
   - Zod schemas for RFC 7591 data structures
   - ClientMetadata: Client registration metadata
   - RegistrationRequest: Client registration request payload
   - RegistrationResponse: Server registration response
   - ErrorResponse: RFC 7591 error responses
   - ValidationResult: Compliance validation results

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

Tests in [src/tests/validator.test.ts](src/tests/validator.test.ts) cover:
- Valid and invalid registration responses
- Metadata validation edge cases
- Redirect URI security validation
- Grant type consistency checks
- URI and email format validation

Use Vitest for unit tests with coverage reporting.

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
