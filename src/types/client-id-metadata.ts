import { z } from 'zod';

/**
 * Client ID Metadata Document
 * https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
 *
 * MCP 2025-11-25 specification allows HTTPS URLs as client identifiers
 * that resolve to metadata documents.
 */
export const ClientIDMetadataDocumentSchema = z.object({
  // Required fields per MCP 2025-11-25 spec
  client_id: z.string().url(), // Must be HTTPS URL with path component
  client_name: z.string(),
  redirect_uris: z.array(z.string().url()),

  // Optional fields (same as RFC 7591 client metadata)
  token_endpoint_auth_method: z
    .enum([
      'none',
      'client_secret_post',
      'client_secret_basic',
      'client_secret_jwt',
      'private_key_jwt'
    ])
    .optional(),

  grant_types: z
    .array(
      z.enum([
        'authorization_code',
        'implicit',
        'password',
        'client_credentials',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'urn:ietf:params:oauth:grant-type:saml2-bearer'
      ])
    )
    .optional(),

  response_types: z.array(z.string()).optional(),
  client_uri: z.string().url().optional(),
  logo_uri: z.string().url().optional(),
  contacts: z.array(z.string().email()).optional(),
  tos_uri: z.string().url().optional(),
  policy_uri: z.string().url().optional(),
  jwks_uri: z.string().url().optional(),
  jwks: z.object({}).optional(),
  software_id: z.string().optional(),
  software_version: z.string().optional(),
  scope: z.string().optional()
});

export type ClientIDMetadataDocument = z.infer<typeof ClientIDMetadataDocumentSchema>;

/**
 * Validate that a client_id is a valid URL with path component
 * Allows HTTP for localhost/development, but HTTPS is required for production
 */
export function isValidClientIDUrl(clientId: string): boolean {
  try {
    const url = new URL(clientId);

    // Must use HTTPS or HTTP (HTTP allowed for localhost only in practice)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      return false;
    }

    // Must have a path component (not just domain)
    if (!url.pathname || url.pathname === '/') {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Check if URL should use HTTPS in production
 */
export function shouldUseHTTPS(clientId: string): { valid: boolean; reason?: string } {
  try {
    const url = new URL(clientId);
    const isLocalhost = url.hostname === 'localhost' ||
                       url.hostname === '127.0.0.1' ||
                       url.hostname === '::1' ||
                       url.hostname.endsWith('.local');

    if (url.protocol === 'http:' && !isLocalhost) {
      return {
        valid: false,
        reason: 'HTTP is not allowed for non-localhost URLs in production'
      };
    }

    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      return {
        valid: false,
        reason: 'URL must use HTTPS or HTTP protocol'
      };
    }

    return { valid: true };
  } catch {
    return { valid: false, reason: 'Invalid URL format' };
  }
}

/**
 * Fetch and parse a Client ID Metadata Document from an HTTPS URL
 */
export async function fetchClientIDMetadataDocument(
  clientId: string,
  enableDebug: boolean = false
): Promise<ClientIDMetadataDocument> {
  if (!isValidClientIDUrl(clientId)) {
    throw new Error(
      'Invalid client_id URL: must be HTTPS with path component'
    );
  }

  const requestHeaders = {
    Accept: 'application/json'
  };

  const response = await fetch(clientId, {
    method: 'GET',
    headers: requestHeaders
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Failed to fetch Client ID Metadata Document: ${response.status} ${response.statusText}`
    );
  }

  const responseText = await response.text();

  let data;
  try {
    data = JSON.parse(responseText);
  } catch (error) {
    throw new Error(
      `Failed to parse Client ID Metadata Document as JSON: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  // Validate the document
  const document = ClientIDMetadataDocumentSchema.parse(data);

  // Verify client_id in document matches the URL
  if (document.client_id !== clientId) {
    throw new Error(
      `client_id in metadata document (${document.client_id}) does not match URL (${clientId})`
    );
  }

  return document;
}

/**
 * Validation result for Client ID Metadata Document
 */
export interface ClientIDMetadataValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  document?: ClientIDMetadataDocument;
  debug?: {
    request?: {
      url?: string;
      method?: string;
      headers?: Record<string, string>;
    };
    response?: {
      status?: number;
      statusText?: string;
      headers?: Record<string, string>;
      body?: string;
    };
  };
}

/**
 * Validate a Client ID Metadata Document
 */
export async function validateClientIDMetadataDocument(
  clientId: string,
  enableDebug: boolean = false
): Promise<ClientIDMetadataValidationResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const debugInfo: ClientIDMetadataValidationResult['debug'] = enableDebug ? {} : undefined;

  // Check URL format
  if (!isValidClientIDUrl(clientId)) {
    errors.push('client_id must be an HTTPS URL with a path component');
    return { valid: false, errors, warnings, debug: debugInfo };
  }

  const requestHeaders = {
    Accept: 'application/json'
  };

  if (enableDebug) {
    debugInfo!.request = {
      url: clientId,
      method: 'GET',
      headers: requestHeaders
    };
  }

  try {
    let response: Response;
    try {
      response = await fetch(clientId, {
        method: 'GET',
        headers: requestHeaders
      });
    } catch (fetchError) {
      // Fetch failed at network level
      if (enableDebug) {
        debugInfo!.response = {
          status: 0,
          statusText: 'Network Error',
          headers: {},
          body: `Fetch failed: ${fetchError instanceof Error ? fetchError.message : String(fetchError)}`
        };
      }
      throw fetchError;
    }

    const responseHeaders = Object.fromEntries(response.headers.entries());

    if (!response.ok) {
      const errorBody = await response.text();

      if (enableDebug) {
        debugInfo!.response = {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
          body: errorBody
        };
      }

      errors.push(`Failed to fetch metadata document: ${response.status} ${response.statusText}`);
      return { valid: false, errors, warnings, debug: debugInfo };
    }

    const responseText = await response.text();

    if (enableDebug) {
      debugInfo!.response = {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body: responseText
      };
    }

    let data;
    try {
      data = JSON.parse(responseText);
    } catch (error) {
      errors.push(`Failed to parse metadata document as JSON: ${error instanceof Error ? error.message : String(error)}`);
      return { valid: false, errors, warnings, debug: debugInfo };
    }

    // Validate the document schema
    let document: ClientIDMetadataDocument;
    try {
      document = ClientIDMetadataDocumentSchema.parse(data);
    } catch (error) {
      errors.push(`Invalid metadata document schema: ${error instanceof Error ? error.message : String(error)}`);
      return { valid: false, errors, warnings, debug: debugInfo };
    }

    // Verify client_id in document matches the URL
    if (document.client_id !== clientId) {
      errors.push(`client_id in metadata document (${document.client_id}) does not match URL (${clientId})`);
    }

    // Validate required fields are present
    if (!document.client_name) {
      errors.push('Missing required field: client_name');
    }

    if (!document.redirect_uris || document.redirect_uris.length === 0) {
      errors.push('Missing required field: redirect_uris');
    }

    // Validate redirect URIs use HTTPS
    if (document.redirect_uris) {
      for (const uri of document.redirect_uris) {
        try {
          const url = new URL(uri);
          if (url.protocol !== 'https:' && url.protocol !== 'http:') {
            warnings.push(`Redirect URI uses custom scheme: ${uri}`);
          } else if (url.protocol === 'http:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
            errors.push(`Redirect URI must use HTTPS (not HTTP) for non-localhost: ${uri}`);
          }
        } catch {
          errors.push(`Invalid redirect URI format: ${uri}`);
        }
      }
    }

    // Validate private_key_jwt has JWKS
    if (document.token_endpoint_auth_method === 'private_key_jwt') {
      if (!document.jwks_uri && !document.jwks) {
        errors.push('private_key_jwt authentication requires jwks_uri or jwks');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      document: errors.length === 0 ? document : undefined,
      debug: debugInfo
    };
  } catch (error) {
    errors.push(`Failed to fetch or parse metadata document: ${error instanceof Error ? error.message : String(error)}`);
    return { valid: false, errors, warnings, debug: debugInfo };
  }
}
