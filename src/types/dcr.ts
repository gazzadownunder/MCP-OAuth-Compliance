import { z } from 'zod';

/**
 * RFC 7591 Client Metadata Schema
 * https://datatracker.ietf.org/doc/html/rfc7591#section-2
 */
export const ClientMetadataSchema = z.object({
  // Required for redirect-based flows
  redirect_uris: z.array(z.string().url()).optional(),

  // Client authentication
  token_endpoint_auth_method: z
    .enum([
      'none',
      'client_secret_post',
      'client_secret_basic',
      'client_secret_jwt',
      'private_key_jwt'
    ])
    .optional(),

  // Grant types
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

  // Response types
  response_types: z.array(z.string()).optional(),

  // Human-readable client information
  client_name: z.string().optional(),
  client_uri: z.string().url().optional(),
  logo_uri: z.string().url().optional(),

  // Contact information
  contacts: z.array(z.string().email()).optional(),

  // Legal information
  tos_uri: z.string().url().optional(),
  policy_uri: z.string().url().optional(),

  // JSON Web Key Set
  jwks_uri: z.string().url().optional(),
  jwks: z.object({}).optional(),

  // Software information
  software_id: z.string().optional(),
  software_version: z.string().optional(),
  software_statement: z.string().optional(),

  // Scope
  scope: z.string().optional()
});

export type ClientMetadata = z.infer<typeof ClientMetadataSchema>;

/**
 * RFC 7591 Client Registration Request
 */
export const RegistrationRequestSchema = ClientMetadataSchema.extend({
  // Initial access token (if required by server)
  token: z.string().optional()
});

export type RegistrationRequest = z.infer<typeof RegistrationRequestSchema>;

/**
 * RFC 7591 Client Registration Response
 * https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
 */
export const RegistrationResponseSchema = ClientMetadataSchema.extend({
  // Required fields
  client_id: z.string(),

  // Optional fields
  client_secret: z.string().optional(),
  client_id_issued_at: z.number().int().optional(),
  client_secret_expires_at: z.number().int().optional(),

  // Registration management
  // NOTE: RFC 7592 requires fully qualified URL, but some servers return relative paths
  // Accept string to allow validation, actual URL validation happens in compliance tests
  registration_client_uri: z.string().optional(),
  registration_access_token: z.string().optional()
});

export type RegistrationResponse = z.infer<typeof RegistrationResponseSchema>;

/**
 * RFC 7591 Error Response
 * https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
 */
export const ErrorResponseSchema = z.object({
  error: z.enum([
    'invalid_redirect_uri',
    'invalid_client_metadata',
    'invalid_software_statement',
    'unapproved_software_statement'
  ]),
  error_description: z.string().optional()
});

export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;

/**
 * Validation result for RFC 7591 compliance
 */
export interface ValidationResult {
  compliant: boolean;
  errors: string[];
  warnings: string[];
}
