import crypto from 'crypto';

/**
 * PKCE (Proof Key for Code Exchange) utilities
 * RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
 */

/**
 * Generate a cryptographically random code verifier
 * Must be 43-128 characters long, using [A-Z][a-z][0-9]-._~
 */
export function generateCodeVerifier(): string {
  const buffer = crypto.randomBytes(32);
  return base64URLEncode(buffer);
}

/**
 * Generate code challenge from verifier using S256 method
 * code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
 */
export function generateCodeChallenge(verifier: string): string {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return base64URLEncode(hash);
}

/**
 * Base64-URL-encode a buffer (RFC 7636 Appendix A)
 */
function base64URLEncode(buffer: Buffer): string {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Generate a random state parameter for CSRF protection
 */
export function generateState(): string {
  return base64URLEncode(crypto.randomBytes(32));
}

/**
 * PKCE parameters for authorization flow
 */
export interface PKCEParams {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
}

/**
 * Generate all PKCE parameters needed for authorization
 */
export function generatePKCEParams(): PKCEParams {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = generateState();

  return {
    codeVerifier,
    codeChallenge,
    state
  };
}
