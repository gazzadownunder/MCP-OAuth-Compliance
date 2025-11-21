import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DiscoveryClient } from '../client/discovery.js';
import { getWellKnownUri } from '../types/oauth-discovery.js';

// Mock fetch globally
global.fetch = vi.fn();

describe('DiscoveryClient', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getWellKnownUri', () => {
    it('should construct well-known URI for root issuer', () => {
      const uri = getWellKnownUri('https://example.com');
      expect(uri).toBe('https://example.com/.well-known/oauth-authorization-server');
    });

    it('should construct well-known URI for issuer with path', () => {
      const uri = getWellKnownUri('https://example.com/auth');
      expect(uri).toBe('https://example.com/.well-known/oauth-authorization-server/auth');
    });

    it('should handle trailing slash', () => {
      const uri = getWellKnownUri('https://example.com/');
      expect(uri).toBe('https://example.com/.well-known/oauth-authorization-server');
    });
  });

  describe('discover', () => {
    it('should discover server metadata successfully', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/authorize',
        token_endpoint: 'https://example.com/token',
        registration_endpoint: 'https://example.com/register',
        response_types_supported: ['code', 'token']
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockMetadata
      });

      const client = new DiscoveryClient('https://example.com');
      const metadata = await client.discover();

      expect(metadata.issuer).toBe('https://example.com');
      expect(metadata.registration_endpoint).toBe('https://example.com/register');
    });

    it('should throw error when discovery fails', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found'
      });

      const client = new DiscoveryClient('https://example.com');

      await expect(client.discover()).rejects.toThrow('Discovery failed');
    });

    it('should throw error when issuer does not match', async () => {
      const mockMetadata = {
        issuer: 'https://different.com',
        registration_endpoint: 'https://example.com/register'
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockMetadata
      });

      const client = new DiscoveryClient('https://example.com');

      await expect(client.discover()).rejects.toThrow('Issuer mismatch');
    });

    it('should throw error when content-type is not JSON', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/html' }),
        json: async () => ({})
      });

      const client = new DiscoveryClient('https://example.com');

      await expect(client.discover()).rejects.toThrow('non-JSON content type');
    });
  });

  describe('getRegistrationEndpoint', () => {
    it('should return registration endpoint from metadata', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        registration_endpoint: 'https://example.com/register'
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockMetadata
      });

      const client = new DiscoveryClient('https://example.com');
      const endpoint = await client.getRegistrationEndpoint();

      expect(endpoint).toBe('https://example.com/register');
    });

    it('should throw error when registration endpoint is not present', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/authorize'
        // No registration_endpoint
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockMetadata
      });

      const client = new DiscoveryClient('https://example.com');

      await expect(client.getRegistrationEndpoint()).rejects.toThrow(
        'does not support dynamic client registration'
      );
    });
  });

  describe('supportsGrantType', () => {
    it('should return true when grant type is supported', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        grant_types_supported: ['authorization_code', 'refresh_token']
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockMetadata
      });

      const client = new DiscoveryClient('https://example.com');
      const supports = await client.supportsGrantType('authorization_code');

      expect(supports).toBe(true);
    });

    it('should return false when grant type is not supported', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        grant_types_supported: ['authorization_code']
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockMetadata
      });

      const client = new DiscoveryClient('https://example.com');
      const supports = await client.supportsGrantType('implicit');

      expect(supports).toBe(false);
    });
  });
});
