/**
 * OAuth 2.1 Flow Utilities
 *
 * Provides utilities for building OAuth authorization and token requests
 * with support for:
 * - PKCE (RFC 7636)
 * - Resource Parameters (RFC 8707) - MCP 2025-11-25
 * - Standard OAuth 2.1 flows
 */

import { TokenResponse, TokenResponseSchema } from '../types/token.js';
import { fetchWithDebug } from './fetch-with-debug.js';

/**
 * Authorization Request Parameters
 */
export interface AuthorizationRequestParams {
  /** Authorization endpoint URL */
  authorizationEndpoint: string;
  /** Client identifier */
  clientId: string;
  /** Redirect URI for callback */
  redirectUri: string;
  /** Requested scope (space-separated) */
  scope: string;
  /** State parameter for CSRF protection */
  state: string;

  // PKCE parameters (RFC 7636)
  /** Code challenge derived from code verifier */
  codeChallenge: string;
  /** Code challenge method: 'S256' or 'plain' */
  codeChallengeMethod: 'S256' | 'plain';

  // Optional parameters
  /** Nonce for OpenID Connect */
  nonce?: string;
  /** Resource parameter (RFC 8707) - MCP 2025-11-25 */
  resource?: string;
  /** Additional custom parameters */
  additionalParams?: Record<string, string>;
}

/**
 * Token Request Parameters
 */
export interface TokenRequestParams {
  /** Token endpoint URL */
  tokenEndpoint: string;
  /** Client identifier */
  clientId: string;
  /** Authorization code from callback */
  code: string;
  /** Redirect URI (must match authorization request) */
  redirectUri: string;
  /** Code verifier for PKCE */
  codeVerifier: string;

  // Optional authentication
  /** Client secret (for confidential clients) */
  clientSecret?: string;

  // Private Key JWT authentication (RFC 7523) - MCP 2025-11-25
  /** Use private_key_jwt authentication instead of client_secret */
  usePrivateKeyJWT?: boolean;
  /** JWT assertion for private_key_jwt authentication */
  clientAssertion?: string;

  // RFC 8707 Resource Parameter (MCP 2025-11-25)
  /** Resource parameter (should match authorization request) */
  resource?: string;

  // Additional parameters
  /** Additional custom parameters */
  additionalParams?: Record<string, string>;
}

/**
 * Build authorization URL for OAuth 2.1 flow
 *
 * @param params - Authorization request parameters
 * @returns Complete authorization URL
 */
export function buildAuthorizationUrl(params: AuthorizationRequestParams): string {
  const url = new URL(params.authorizationEndpoint);

  // Required OAuth 2.1 parameters
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('scope', params.scope);
  url.searchParams.set('state', params.state);

  // PKCE parameters (RFC 7636)
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', params.codeChallengeMethod);

  // Optional: Nonce (OpenID Connect)
  if (params.nonce) {
    url.searchParams.set('nonce', params.nonce);
  }

  // Optional: Resource parameter (RFC 8707) - MCP 2025-11-25
  if (params.resource) {
    url.searchParams.set('resource', params.resource);
  }

  // Additional custom parameters
  if (params.additionalParams) {
    for (const [key, value] of Object.entries(params.additionalParams)) {
      url.searchParams.set(key, value);
    }
  }

  return url.toString();
}

/**
 * Exchange authorization code for access token
 *
 * @param params - Token request parameters
 * @returns Token response
 */
export async function exchangeCodeForToken(
  params: TokenRequestParams
): Promise<TokenResponse> {
  // Build request body
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    code_verifier: params.codeVerifier
  });

  // Add client authentication
  if (params.usePrivateKeyJWT && params.clientAssertion) {
    // Private Key JWT authentication (RFC 7523) - MCP 2025-11-25
    // Note: client_id is NOT included when using client_assertion
    body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    body.set('client_assertion', params.clientAssertion);
  } else {
    // Standard client authentication
    body.set('client_id', params.clientId);

    // Add client secret if provided (confidential client)
    if (params.clientSecret) {
      body.set('client_secret', params.clientSecret);
    }
  }

  // Add resource parameter if provided (RFC 8707 - MCP 2025-11-25)
  if (params.resource) {
    body.set('resource', params.resource);
  }

  // Add additional parameters
  if (params.additionalParams) {
    for (const [key, value] of Object.entries(params.additionalParams)) {
      body.set(key, value);
    }
  }

  // Make token request
  const response = await fetchWithDebug(params.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    },
    body: body.toString(),
    debugLabel: 'Token Exchange Request'
  });

  // Parse response
  const responseData = await response.json();

  if (!response.ok) {
    throw new TokenRequestError(
      `Token request failed: ${response.status} ${response.statusText}`,
      response.status,
      responseData
    );
  }

  // Validate response against schema
  const parseResult = TokenResponseSchema.safeParse(responseData);

  if (!parseResult.success) {
    throw new TokenRequestError(
      'Invalid token response format',
      response.status,
      responseData,
      parseResult.error.errors.map((e: any) => `${e.path.join('.')}: ${e.message}`)
    );
  }

  return parseResult.data;
}

/**
 * Refresh access token using refresh token
 *
 * @param tokenEndpoint - Token endpoint URL
 * @param clientId - Client identifier
 * @param refreshToken - Refresh token
 * @param clientSecret - Client secret (optional)
 * @param scope - Requested scope (optional, defaults to original)
 * @param resource - Resource parameter (RFC 8707)
 * @returns Token response
 */
export async function refreshAccessToken(
  tokenEndpoint: string,
  clientId: string,
  refreshToken: string,
  clientSecret?: string,
  scope?: string,
  resource?: string
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId
  });

  if (clientSecret) {
    body.set('client_secret', clientSecret);
  }

  if (scope) {
    body.set('scope', scope);
  }

  if (resource) {
    body.set('resource', resource);
  }

  const response = await fetchWithDebug(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    },
    body: body.toString(),
    debugLabel: 'Token Refresh Request'
  });

  const responseData = await response.json();

  if (!response.ok) {
    throw new TokenRequestError(
      `Token refresh failed: ${response.status} ${response.statusText}`,
      response.status,
      responseData
    );
  }

  const parseResult = TokenResponseSchema.safeParse(responseData);

  if (!parseResult.success) {
    throw new TokenRequestError(
      'Invalid token response format',
      response.status,
      responseData,
      parseResult.error.errors.map((e: any) => `${e.path.join('.')}: ${e.message}`)
    );
  }

  return parseResult.data;
}

/**
 * Parse authorization callback parameters
 *
 * @param callbackUrl - The callback URL with query parameters
 * @returns Parsed parameters including code, state, and any errors
 */
export function parseAuthorizationCallback(callbackUrl: string): {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
  error_uri?: string;
} {
  const url = new URL(callbackUrl);
  const params = url.searchParams;

  return {
    code: params.get('code') || undefined,
    state: params.get('state') || undefined,
    error: params.get('error') || undefined,
    error_description: params.get('error_description') || undefined,
    error_uri: params.get('error_uri') || undefined
  };
}

/**
 * Validate state parameter matches expected value
 *
 * @param receivedState - State from callback
 * @param expectedState - Expected state value
 * @throws Error if state doesn't match
 */
export function validateState(receivedState: string | undefined, expectedState: string): void {
  if (!receivedState) {
    throw new Error('Missing state parameter in authorization callback');
  }

  if (receivedState !== expectedState) {
    throw new Error(
      'State parameter mismatch - possible CSRF attack. ' +
      'Received state does not match expected value.'
    );
  }
}

/**
 * Token Request Error
 */
export class TokenRequestError extends Error {
  constructor(
    message: string,
    public status: number,
    public response: any,
    public validationErrors?: string[]
  ) {
    super(message);
    this.name = 'TokenRequestError';
  }
}
