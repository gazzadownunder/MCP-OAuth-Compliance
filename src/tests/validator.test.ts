import { describe, it, expect } from 'vitest';
import { RFC7591Validator } from '../validation/rfc7591-validator.js';
import { RegistrationResponse, ClientMetadata } from '../types/dcr.js';

describe('RFC7591Validator', () => {
  const validator = new RFC7591Validator();

  describe('validateRegistrationResponse', () => {
    it('should validate a compliant response', () => {
      const response: RegistrationResponse = {
        client_id: 'test-client-123',
        client_secret: 'secret-xyz',
        client_id_issued_at: 1234567890,
        client_secret_expires_at: 0,
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const result = validator.validateRegistrationResponse(response);

      expect(result.compliant).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject response without client_id', () => {
      const response = {
        client_secret: 'secret-xyz'
      } as RegistrationResponse;

      const result = validator.validateRegistrationResponse(response);

      expect(result.compliant).toBe(false);
      expect(result.errors).toContain('Missing required field: client_id');
    });

    it('should reject invalid redirect URIs', () => {
      const response: RegistrationResponse = {
        client_id: 'test-client-123',
        redirect_uris: ['http://example.com/callback'] // HTTP not allowed except localhost
      };

      const result = validator.validateRegistrationResponse(response);

      expect(result.compliant).toBe(false);
      expect(result.errors.some(e => e.includes('Invalid redirect_uri'))).toBe(true);
    });

    it('should accept localhost HTTP redirect URIs', () => {
      const response: RegistrationResponse = {
        client_id: 'test-client-123',
        redirect_uris: ['http://localhost:8080/callback', 'http://127.0.0.1:3000/callback']
      };

      const result = validator.validateRegistrationResponse(response);

      expect(result.compliant).toBe(true);
    });

    it('should accept custom scheme redirect URIs', () => {
      const response: RegistrationResponse = {
        client_id: 'test-client-123',
        redirect_uris: ['myapp://callback']
      };

      const result = validator.validateRegistrationResponse(response);

      expect(result.compliant).toBe(true);
    });

    it('should validate authorization_code grant requires redirect_uris', () => {
      const response: RegistrationResponse = {
        client_id: 'test-client-123',
        grant_types: ['authorization_code']
        // Missing redirect_uris
      };

      const result = validator.validateRegistrationResponse(response);

      expect(result.compliant).toBe(false);
      expect(result.errors).toContain('authorization_code grant type requires redirect_uris');
    });

    it('should reject negative timestamps', () => {
      const response: RegistrationResponse = {
        client_id: 'test-client-123',
        client_id_issued_at: -1
      };

      const result = validator.validateRegistrationResponse(response);

      expect(result.compliant).toBe(false);
      expect(result.errors).toContain('client_id_issued_at must be non-negative');
    });

    it('should reject invalid URIs', () => {
      const response: RegistrationResponse = {
        client_id: 'test-client-123',
        client_uri: 'not-a-valid-uri'
      };

      const result = validator.validateRegistrationResponse(response);

      expect(result.compliant).toBe(false);
      expect(result.errors.some(e => e.includes('Invalid URI'))).toBe(true);
    });

    it('should reject invalid email contacts', () => {
      const response: RegistrationResponse = {
        client_id: 'test-client-123',
        contacts: ['not-an-email']
      };

      const result = validator.validateRegistrationResponse(response);

      expect(result.compliant).toBe(false);
      expect(result.errors.some(e => e.includes('Invalid email'))).toBe(true);
    });
  });

  describe('validateClientMetadata', () => {
    it('should validate compliant metadata', () => {
      const metadata: ClientMetadata = {
        client_name: 'Test Client',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic'
      };

      const result = validator.validateClientMetadata(metadata);

      expect(result.compliant).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should require redirect_uris for authorization_code grant', () => {
      const metadata: ClientMetadata = {
        client_name: 'Test Client',
        grant_types: ['authorization_code']
        // Missing redirect_uris
      };

      const result = validator.validateClientMetadata(metadata);

      expect(result.compliant).toBe(false);
      expect(result.errors).toContain('redirect_uris is required for redirect-based flows');
    });

    it('should require redirect_uris for implicit grant', () => {
      const metadata: ClientMetadata = {
        client_name: 'Test Client',
        grant_types: ['implicit']
        // Missing redirect_uris
      };

      const result = validator.validateClientMetadata(metadata);

      expect(result.compliant).toBe(false);
      expect(result.errors).toContain('redirect_uris is required for redirect-based flows');
    });

    it('should not require redirect_uris for client_credentials grant', () => {
      const metadata: ClientMetadata = {
        client_name: 'Test Client',
        grant_types: ['client_credentials']
        // No redirect_uris needed
      };

      const result = validator.validateClientMetadata(metadata);

      expect(result.compliant).toBe(true);
    });

    it('should warn about JWT auth methods without jwks', () => {
      const metadata: ClientMetadata = {
        client_name: 'Test Client',
        token_endpoint_auth_method: 'private_key_jwt'
        // Missing jwks_uri or jwks
      };

      const result = validator.validateClientMetadata(metadata);

      expect(result.compliant).toBe(true); // Warning, not error
      expect(result.warnings.some(w => w.includes('requires jwks'))).toBe(true);
    });
  });
});
