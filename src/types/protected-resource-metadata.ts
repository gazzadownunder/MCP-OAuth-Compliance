import { z } from 'zod';

/**
 * RFC 9728 OAuth 2.0 Protected Resource Metadata
 * https://datatracker.ietf.org/doc/html/rfc9728
 */
export const ProtectedResourceMetadataSchema = z
  .object({
    // Resource identifier
    resource: z.string().url().optional(),

    // Authorization servers (required)
    authorization_servers: z.array(z.string().url()),

    // Token endpoint auth methods
    bearer_methods_supported: z.array(z.string()).optional(),
    resource_signing_alg_values_supported: z.array(z.string()).optional(),

    // Scopes
    scopes_supported: z.array(z.string()).optional(),
    resource_documentation: z.string().url().optional()
  })
  .passthrough();

export type ProtectedResourceMetadata = z.infer<typeof ProtectedResourceMetadataSchema>;

/**
 * Construct well-known URI for Protected Resource Metadata
 * https://datatracker.ietf.org/doc/html/rfc9728#section-3
 */
export function getProtectedResourceMetadataUri(serverUrl: string): string {
  const url = new URL(serverUrl);

  // Try with path component first
  if (url.pathname !== '/' && url.pathname !== '') {
    return `${url.origin}/.well-known/oauth-protected-resource${url.pathname}`;
  }

  // Fallback to root
  return `${url.origin}/.well-known/oauth-protected-resource`;
}

/**
 * Parse WWW-Authenticate header to extract resource_metadata URL
 */
export function parseWWWAuthenticateHeader(header: string): string | null {
  const resourceMetadataMatch = header.match(/resource_metadata="([^"]+)"/);
  return resourceMetadataMatch ? resourceMetadataMatch[1] : null;
}
