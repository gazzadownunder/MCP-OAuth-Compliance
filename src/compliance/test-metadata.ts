/**
 * RFC Test Metadata - Provides detailed references, expected values, and remediation guidance
 */

export interface TestMetadata {
  rfcReference: string;
  rfcUrl: string;
  expected: string;
  remediation: string;
}

export const TEST_METADATA: Record<string, TestMetadata> = {
  'prm-1.1': {
    rfcReference: 'RFC 9728 Section 2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-2',
    expected: 'HTTP 401 Unauthorized response',
    remediation:
      'Configure your MCP server to return HTTP 401 when an unauthenticated request is made to a protected resource. The response should include a WWW-Authenticate header.'
  },
  'prm-1.2': {
    rfcReference: 'RFC 9728 Section 2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-2',
    expected: 'WWW-Authenticate: Bearer resource_metadata="<uri>"',
    remediation:
      'Add a WWW-Authenticate header to your 401 response with the Bearer scheme and resource_metadata parameter pointing to your Protected Resource Metadata document.\n\nExample: WWW-Authenticate: Bearer resource_metadata="https://your-server/.well-known/oauth-protected-resource"'
  },
  'prm-1.3': {
    rfcReference: 'RFC 9728 Section 2.1',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-2.1',
    expected: 'resource_metadata parameter in WWW-Authenticate header',
    remediation:
      'Include the resource_metadata parameter (note: underscore, not hyphen) in your WWW-Authenticate header. This parameter should contain the URI to your Protected Resource Metadata document.\n\nExample: resource_metadata="https://your-server/.well-known/oauth-protected-resource"'
  },
  'prm-1.4': {
    rfcReference: 'RFC 9728 Section 2.1',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-2.1',
    expected: 'PRM document at the URI specified in resource_metadata parameter',
    remediation:
      'Ensure the URI provided in the resource_metadata parameter of your WWW-Authenticate header returns a valid PRM document.\n\nThe response must be JSON with Content-Type: application/json.'
  },
  'prm-1.5': {
    rfcReference: 'MCP Draft Section 4.2.2',
    rfcUrl: 'https://spec.modelcontextprotocol.io/specification/draft/basic/authentication/',
    expected: 'PRM at path-specific well-known URI',
    remediation:
      'For MCP servers with specific paths (e.g., /public/mcp), you can optionally host the PRM at:\n\nhttps://your-server/.well-known/oauth-protected-resource/your/path\n\nThis allows path-specific metadata while following the well-known URI convention.'
  },
  'prm-1.6': {
    rfcReference: 'RFC 9728 Section 3',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-3',
    expected: 'PRM at /.well-known/oauth-protected-resource',
    remediation:
      'Host your Protected Resource Metadata document at the standard well-known URI:\n\nhttps://your-server/.well-known/oauth-protected-resource\n\nThis is the primary discovery method per RFC 9728.'
  },
  'prm-1.7': {
    rfcReference: 'RFC 8414 Section 3',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-3',
    expected: 'Metadata at OAuth AS well-known URI (fallback)',
    remediation:
      'As a fallback, clients may check the OAuth AS well-known URI. This is not the primary method but can work if your server structure combines both.'
  },
  'prm-1.8': {
    rfcReference: 'RFC 9728 Section 3',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc9728.html#section-3',
    expected: 'authorization_servers array in PRM document',
    remediation:
      'Add an "authorization_servers" field to your Protected Resource Metadata document. This should be a JSON array containing the issuer identifiers of authorization servers that can be used to access this resource.\n\nExample:\n{\n  "resource": "https://your-server/mcp",\n  "authorization_servers": ["https://your-auth-server"],\n  "scopes_supported": ["read", "write"]\n}'
  },
  'as-2.1': {
    rfcReference: 'RFC 8414 Section 3',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-3',
    expected: 'Authorization Server Metadata at /.well-known/oauth-authorization-server',
    remediation:
      'Host your Authorization Server Metadata document at: <issuer>/.well-known/oauth-authorization-server\n\nThe document must be a JSON object containing the required metadata fields including issuer, authorization_endpoint, token_endpoint, and other OAuth 2.0 configuration.'
  },
  'as-2.3': {
    rfcReference: 'RFC 8414 Section 2 (authorization_endpoint)',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-2',
    expected: 'authorization_endpoint in AS metadata',
    remediation:
      'Add the "authorization_endpoint" field to your Authorization Server Metadata. This is REQUIRED per RFC 8414.\n\nExample: "authorization_endpoint": "https://your-auth-server/authorize"'
  },
  'as-2.4': {
    rfcReference: 'RFC 8414 Section 2 (token_endpoint)',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-2',
    expected: 'token_endpoint in AS metadata',
    remediation:
      'Add the "token_endpoint" field to your Authorization Server Metadata. This is REQUIRED per RFC 8414 unless only the implicit grant type is supported.\n\nExample: "token_endpoint": "https://your-auth-server/token"'
  },
  'dcr-3.1': {
    rfcReference: 'RFC 7591 Section 3',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7591.html#section-3',
    expected: 'Registration endpoint accepts HTTP POST',
    remediation:
      'Ensure your registration endpoint accepts POST requests with Content-Type: application/json. The endpoint should process client metadata and return a registration response.'
  },
  'dcr-3.2': {
    rfcReference: 'RFC 7591 Section 3.2.1',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7591.html#section-3.2.1',
    expected: 'HTTP 201 Created status code',
    remediation:
      'RFC 7591 explicitly requires HTTP 201 Created for successful registration responses, not 200 OK. Update your registration endpoint to return 201.\n\nThe response must include the client_id and all registered client metadata.'
  },
  'dcr-3.2a': {
    rfcReference: 'RFC 7591 Section 2',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7591.html#section-2',
    expected: 'Server accepts authorization_code grant type without requiring refresh_token',
    remediation:
      'This is a FALLBACK test that attempts registration with refresh_token added to grant_types.\n\nIf this test shows a WARNING (passed), it means your server has stricter requirements than RFC 7591 mandates. RFC 7591 Section 2 does not require refresh_token for client registration.\n\nConsider:\n1. Relaxing validation to accept clients with only authorization_code\n2. Documenting this as a server-specific requirement\n3. Reviewing if this aligns with your security policies'
  },
  'dcr-3.3': {
    rfcReference: 'RFC 7591 Section 3.2.1',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7591.html#section-3.2.1',
    expected: 'client_id field in registration response',
    remediation:
      'The registration response MUST include a "client_id" field. This is the unique identifier assigned to the client.\n\nExample response:\n{\n  "client_id": "s6BhdRkqt3",\n  "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",\n  "client_secret_expires_at": 1577858400,\n  ...\n}'
  },
  'dcr-3.4': {
    rfcReference: 'RFC 7591 Section 3.2.1',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7591.html#section-3.2.1',
    expected: 'client_secret_expires_at when client_secret is issued',
    remediation:
      'When your registration response includes a "client_secret", you MUST also include "client_secret_expires_at". This field indicates when the secret expires (Unix timestamp) or 0 if it never expires.\n\nExample: "client_secret_expires_at": 0'
  },
  'oauth-4.1': {
    rfcReference: 'RFC 8414 Section 2 (grant_types_supported)',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8414.html#section-2',
    expected: 'authorization_code in grant_types_supported or field omitted',
    remediation:
      'Ensure your Authorization Server supports the authorization_code grant type. Either include it explicitly in grant_types_supported or omit the field (defaults to ["authorization_code", "implicit"]).\n\nExample: "grant_types_supported": ["authorization_code", "refresh_token"]'
  },
  'oauth-4.2': {
    rfcReference: 'RFC 7636 (PKCE)',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7636.html',
    expected: 'S256 in code_challenge_methods_supported',
    remediation:
      'Add PKCE support to your authorization server. Advertise this by including "code_challenge_methods_supported": ["S256"] in your AS metadata.\n\nPKCE is essential for public clients and OAuth 2.1 compliance.'
  },
  'oauth-4.3': {
    rfcReference: 'RFC 6749 Section 10.12 (CSRF Protection)',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12',
    expected: 'Authorization endpoint returns matching state parameter',
    remediation:
      'The authorization server MUST return the exact same "state" parameter value that was sent in the authorization request. This prevents CSRF attacks.\n\nEnsure your authorization endpoint echoes back the state parameter unchanged.'
  },
  'oauth-4.4': {
    rfcReference: 'RFC 7636 Section 4.5 (PKCE Verification)',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc7636.html#section-4.5',
    expected: 'Token endpoint accepts and validates code_verifier',
    remediation:
      "Your token endpoint must:\n1. Accept the code_verifier parameter\n2. Hash it using SHA-256: BASE64URL(SHA256(code_verifier))\n3. Compare the result to the code_challenge from the authorization request\n4. Reject the request if they don't match"
  },
  'oauth-4.5': {
    rfcReference: 'RFC 6749 Section 5.1 (Token Response)',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1',
    expected: 'access_token field in token response',
    remediation:
      'The token response MUST include an "access_token" field. This is the credential used to access protected resources.\n\nExample response:\n{\n  "access_token": "eyJhbG...",\n  "token_type": "Bearer",\n  "expires_in": 3600\n}'
  },
  'oauth-4.6': {
    rfcReference: 'RFC 6750 Section 1 (Bearer Token)',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6750.html#section-1',
    expected: 'token_type: "Bearer"',
    remediation:
      'The token_type field MUST be "Bearer" (case-insensitive). This indicates the token should be sent in the Authorization header as:\n\nAuthorization: Bearer <access_token>'
  },
  'oauth-4.7': {
    rfcReference: 'RFC 6749 Section 5.1',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1',
    expected: 'expires_in field indicating token lifetime',
    remediation:
      'Include "expires_in" field in token response (RECOMMENDED). This tells the client when the access token expires (in seconds from issuance).\n\nExample: "expires_in": 3600 (1 hour)'
  },
  'oauth-4.8': {
    rfcReference: 'RFC 6749 Section 5.1',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1',
    expected: 'refresh_token for long-lived access (OPTIONAL)',
    remediation:
      'If your client requested the "refresh_token" grant type during registration, consider issuing a refresh_token in the token response. This allows clients to obtain new access tokens without user interaction.'
  },
  'oauth-4.9': {
    rfcReference: 'RFC 8707 (Resource Indicators)',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc8707.html',
    expected: 'Token includes audience (aud) claim when resource parameter used',
    remediation:
      'When a client specifies the "resource" parameter in the authorization or token request, the resulting access token should be audience-restricted to that resource.\n\nThis is typically visible in the JWT token\'s "aud" claim.'
  },

  // Step-Up Authorization Tests (MCP 2025-11-25)
  'step-1.0': {
    rfcReference: 'MCP 2025-11-25 Section 10.1',
    rfcUrl: 'https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#section-10.1',
    expected: 'Server implements complete step-up authorization flow',
    remediation:
      'Server must support step-up authorization:\n\n1. Return 403 Forbidden for privileged resources when token has insufficient scope\n2. Include scope challenge in error response\n3. Accept re-authorization with elevated scopes\n4. Issue token with elevated scope\n5. Allow access with elevated token\n\nTest requires configuring a privileged tool that requires elevated scope.'
  },
  'step-1.0.1': {
    rfcReference: 'RFC 6750 Section 3.1',
    rfcUrl: 'https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1',
    expected: 'Server returns 403 Forbidden for insufficient scope',
    remediation:
      'Configure your server to:\n\n1. Check the access token scope claim\n2. Return HTTP 403 Forbidden if the required scope is missing\n3. Include error="insufficient_scope" in the response\n\nExample error response:\n{\n  "error": "insufficient_scope",\n  "error_description": "This tool requires the \'admin\' scope",\n  "scope": "admin"\n}'
  },
  'step-1.0.2': {
    rfcReference: 'MCP 2025-11-25 Section 10.1',
    rfcUrl: 'https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#section-10.1',
    expected: 'Server includes scope information in 403 error response',
    remediation:
      'When returning 403 for insufficient scope, include the required scope in one of these ways:\n\n**Method 1**: Include "scope" field in error response body\n{\n  "error": "insufficient_scope",\n  "scope": "admin"\n}\n\n**Method 2**: Include scope in error_description\n{\n  "error": "insufficient_scope",\n  "error_description": "Requires scope: admin"\n}\n\n**Method 3**: Use WWW-Authenticate header\nWWW-Authenticate: Bearer error="insufficient_scope", scope="admin"'
  },
  'step-1.0.8': {
    rfcReference: 'MCP 2025-11-25 Section 10.1',
    rfcUrl: 'https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#section-10.1',
    expected: 'Server allows access when token contains required elevated scope',
    remediation:
      'After client re-authorizes with elevated scope:\n\n1. Verify the access token now contains the elevated scope in its scope claim\n2. Allow the request to proceed successfully\n3. Return the expected response (200 OK)\n\nExample token scope claim after re-authorization:\n{\n  "scope": "basic admin",  // Now includes both base and elevated scopes\n  "aud": "https://mcp-server.example.com",\n  "iss": "https://as.example.com"\n}'
  },

  // Server Capabilities Discovery Tests
  'cap-10.1': {
    rfcReference: 'MCP Specification - Server Capabilities',
    rfcUrl: 'https://spec.modelcontextprotocol.io/specification/2025-11-25/server/capabilities/',
    expected: 'Successfully initialize authenticated MCP client connection',
    remediation:
      'Ensure your MCP server:\n\n1. Accepts connections with valid OAuth access tokens\n2. Validates the access token before allowing discovery operations\n3. Returns appropriate errors for invalid or expired tokens'
  },
  'cap-10.2': {
    rfcReference: 'MCP Specification - Tools',
    rfcUrl: 'https://spec.modelcontextprotocol.io/specification/2025-11-25/server/tools/',
    expected: 'Server returns list of available tools via tools/list',
    remediation:
      'Implement the tools/list RPC method to return available tools:\n\n{\n  "tools": [\n    {\n      "name": "tool_name",\n      "description": "Tool description",\n      "inputSchema": { ... }\n    }\n  ]\n}\n\nEach tool should include:\n- name: Unique identifier\n- description: What the tool does\n- inputSchema: JSON Schema for tool parameters'
  },
  'cap-10.3': {
    rfcReference: 'MCP Specification - Resources',
    rfcUrl: 'https://spec.modelcontextprotocol.io/specification/2025-11-25/server/resources/',
    expected: 'Server returns list of available resources via resources/list',
    remediation:
      'Implement the resources/list RPC method to return available resources:\n\n{\n  "resources": [\n    {\n      "name": "resource_name",\n      "description": "Resource description",\n      "uri": "resource://uri",\n      "mimeType": "application/json"\n    }\n  ]\n}\n\nEach resource should include:\n- name: Display name\n- description: What the resource provides\n- uri: Unique resource identifier\n- mimeType: Content type (optional)'
  },
  'cap-10.4': {
    rfcReference: 'MCP Specification - Prompts',
    rfcUrl: 'https://spec.modelcontextprotocol.io/specification/2025-11-25/server/prompts/',
    expected: 'Server returns list of available prompts via prompts/list',
    remediation:
      'Implement the prompts/list RPC method to return available prompts:\n\n{\n  "prompts": [\n    {\n      "name": "prompt_name",\n      "description": "Prompt description",\n      "arguments": [\n        {\n          "name": "arg_name",\n          "description": "Argument description",\n          "required": true\n        }\n      ]\n    }\n  ]\n}\n\nEach prompt should include:\n- name: Unique identifier\n- description: What the prompt generates\n- arguments: List of accepted parameters (optional)'
  }
};
