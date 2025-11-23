import { z } from 'zod';

/**
 * RFC 8414 OAuth 2.0 Authorization Server Metadata
 * https://datatracker.ietf.org/doc/html/rfc8414
 */
export const AuthorizationServerMetadataSchema = z
  .object({
    // Required fields
    issuer: z.string().url(),
    authorization_endpoint: z.string().url().optional(),
    token_endpoint: z.string().url().optional(),
    jwks_uri: z.string().url().optional(),
    registration_endpoint: z.string().url().optional(),
    scopes_supported: z.array(z.string()).optional(),

    // Response types
    response_types_supported: z.array(z.string()).optional(),
    response_modes_supported: z.array(z.string()).optional(),

    // Grant types
    grant_types_supported: z.array(z.string()).optional(),

    // Token endpoint auth methods
    token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
    token_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),

    // Service documentation
    service_documentation: z.string().url().optional(),
    ui_locales_supported: z.array(z.string()).optional(),
    op_policy_uri: z.string().url().optional(),
    op_tos_uri: z.string().url().optional(),

    // Revocation
    revocation_endpoint: z.string().url().optional(),
    revocation_endpoint_auth_methods_supported: z.array(z.string()).optional(),

    // Introspection
    introspection_endpoint: z.string().url().optional(),
    introspection_endpoint_auth_methods_supported: z.array(z.string()).optional(),

    // PKCE
    code_challenge_methods_supported: z.array(z.string()).optional()
  })
  .passthrough(); // Allow additional fields

export type AuthorizationServerMetadata = z.infer<typeof AuthorizationServerMetadataSchema>;

/**
 * Construct well-known URI for OAuth Authorization Server Metadata
 * https://datatracker.ietf.org/doc/html/rfc8414#section-3
 */
export function getWellKnownUri(issuer: string): string {
  const url = new URL(issuer);

  // If the issuer has a path component, append to it
  if (url.pathname !== '/' && url.pathname !== '') {
    return `${url.origin}/.well-known/oauth-authorization-server${url.pathname}`;
  }

  // Otherwise, use default path
  return `${url.origin}/.well-known/oauth-authorization-server`;
}
