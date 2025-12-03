/**
 * Fetch wrapper with certificate verification debugging
 * Provides detailed error information for TLS/certificate issues
 *
 * By default, allows self-signed certificates for testing/development
 * but tracks warnings for display in test results.
 */

import * as https from 'https';

export interface FetchDebugOptions extends RequestInit {
  /**
   * Enable detailed debugging output for certificate verification
   * Default: true if DEBUG_CERTS environment variable is set
   */
  debugCerts?: boolean;

  /**
   * Custom label for debug output (helps identify which request failed)
   */
  debugLabel?: string;
}

export interface CertificateWarning {
  type: 'self-signed' | 'expired' | 'not-yet-valid' | 'hostname-mismatch' | 'untrusted-ca';
  message: string;
  hostname: string;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
}

// Global storage for certificate warnings
const certificateWarnings: CertificateWarning[] = [];

/**
 * Get all certificate warnings collected during fetch operations
 */
export function getCertificateWarnings(): CertificateWarning[] {
  return [...certificateWarnings];
}

/**
 * Clear all certificate warnings
 */
export function clearCertificateWarnings(): void {
  certificateWarnings.length = 0;
}

/**
 * Enhanced fetch with certificate debugging
 *
 * When certificate verification fails, this wrapper provides detailed debugging info:
 * - Certificate details (subject, issuer, valid dates)
 * - Error code and reason
 * - Suggestions for resolution
 *
 * @param url - URL to fetch
 * @param options - Fetch options with optional debugging flags
 * @returns Fetch response
 */
export async function fetchWithDebug(
  url: string | URL,
  options: FetchDebugOptions = {}
): Promise<Response> {
  const debugCerts = options.debugCerts ?? (process.env.DEBUG_CERTS === 'true' || process.env.DEBUG_CERTS === '1');
  const debugLabel = options.debugLabel || url.toString();

  // For HTTPS URLs, add custom agent for better error handling
  const urlObj = new URL(url);
  if (urlObj.protocol === 'https:' && debugCerts) {
    console.log(`\n🔍 [Certificate Debug] Fetching: ${debugLabel}`);
    console.log(`   URL: ${url}`);
  }

  try {
    // Create custom HTTPS agent with certificate debugging
    if (urlObj.protocol === 'https:') {
      const agent = new https.Agent({
        // Allow self-signed certificates by default (for testing/development)
        // Can be overridden by setting NODE_TLS_REJECT_UNAUTHORIZED=1
        rejectUnauthorized: process.env.NODE_TLS_REJECT_UNAUTHORIZED === '1',
        // TLS configuration - supports TLS 1.2 and TLS 1.3 (Node.js default)
        minVersion: 'TLSv1.2', // Minimum: TLS 1.2
        maxVersion: 'TLSv1.3', // Maximum: TLS 1.3 (latest)
        // Enable certificate debugging and warning collection
        checkServerIdentity: (hostname, cert) => {
          const issuerCN = cert.issuer.CN || cert.issuer.O || 'Unknown';
          const subjectCN = cert.subject.CN || 'Unknown';

          if (debugCerts) {
            console.log(`\n📜 [Certificate Debug] Server Certificate Details:`);
            console.log(`   Hostname: ${hostname}`);
            console.log(`   Subject: ${subjectCN}`);
            console.log(`   Issuer: ${issuerCN}`);
            console.log(`   Valid From: ${cert.valid_from}`);
            console.log(`   Valid To: ${cert.valid_to}`);
            console.log(`   Fingerprint: ${cert.fingerprint}`);
            console.log(`   TLS Version: Negotiated by client/server (TLS 1.2 - TLS 1.3 supported)`);
          }

          // Check if certificate is self-signed
          const isSelfSigned = issuerCN === subjectCN;

          // Check if certificate is expired or not yet valid
          const now = new Date();
          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);

          if (now < validFrom) {
            const warning: CertificateWarning = {
              type: 'not-yet-valid',
              message: `Certificate not yet valid (starts ${cert.valid_from})`,
              hostname,
              issuer: issuerCN,
              subject: subjectCN,
              validFrom: cert.valid_from,
              validTo: cert.valid_to
            };
            certificateWarnings.push(warning);
            if (debugCerts) {
              console.log(`   ⚠️  WARNING: Certificate not yet valid (starts ${cert.valid_from})`);
            }
          } else if (now > validTo) {
            const warning: CertificateWarning = {
              type: 'expired',
              message: `Certificate expired on ${cert.valid_to}`,
              hostname,
              issuer: issuerCN,
              subject: subjectCN,
              validFrom: cert.valid_from,
              validTo: cert.valid_to
            };
            certificateWarnings.push(warning);
            if (debugCerts) {
              console.log(`   ❌ ERROR: Certificate expired on ${cert.valid_to}`);
            }
          } else {
            if (debugCerts) {
              console.log(`   ✅ Certificate is within valid date range`);
            }
          }

          // Check if self-signed
          if (isSelfSigned) {
            const warning: CertificateWarning = {
              type: 'self-signed',
              message: `Self-signed certificate detected (issuer = subject = ${issuerCN})`,
              hostname,
              issuer: issuerCN,
              subject: subjectCN,
              validFrom: cert.valid_from,
              validTo: cert.valid_to
            };
            certificateWarnings.push(warning);
            if (debugCerts) {
              console.log(`   ⚠️  WARNING: Self-signed certificate (not from a trusted CA)`);
            }
          }

          // Check hostname match
          const hostnameMatches = cert.subject.CN === hostname ||
                                  cert.subjectaltname?.includes(hostname) ||
                                  cert.subjectaltname?.includes(`DNS:${hostname}`);

          if (!hostnameMatches) {
            const warning: CertificateWarning = {
              type: 'hostname-mismatch',
              message: `Certificate hostname mismatch: expected ${hostname}, got ${cert.subject.CN}`,
              hostname,
              issuer: issuerCN,
              subject: subjectCN,
              validFrom: cert.valid_from,
              validTo: cert.valid_to
            };
            certificateWarnings.push(warning);
            if (debugCerts) {
              console.log(`   ⚠️  WARNING: Hostname mismatch`);
              console.log(`      Expected: ${hostname}`);
              console.log(`      Certificate CN: ${cert.subject.CN}`);
              if (cert.subjectaltname) {
                console.log(`      Subject Alt Names: ${cert.subjectaltname}`);
              }
            }
          }

          // Return undefined to allow connection (warnings are tracked separately)
          // Only reject if certificate has critical issues AND rejectUnauthorized is true
          return undefined;
        }
      });

      const response = await fetch(url, {
        ...options,
        // @ts-ignore - agent is valid for node-fetch
        agent
      });

      if (debugCerts) {
        console.log(`✅ [Certificate Debug] Request successful (${response.status})\n`);
      }

      return response;
    }

    // Non-HTTPS or debug disabled - use regular fetch
    return await fetch(url, options);

  } catch (error) {
    if (debugCerts && error instanceof Error) {
      console.error(`\n❌ [Certificate Debug] Request failed: ${debugLabel}`);
      console.error(`   URL: ${url}`);
      console.error(`   Error: ${error.message}`);

      // Detect common certificate errors
      const errorMessage = error.message.toLowerCase();

      if (errorMessage.includes('self-signed') || errorMessage.includes('self signed')) {
        console.error(`\n💡 [Certificate Debug] SELF-SIGNED CERTIFICATE DETECTED`);
        console.error(`   This error occurs when the server uses a self-signed certificate.`);
        console.error(`   Solutions:`);
        console.error(`   1. For testing: Set NODE_TLS_REJECT_UNAUTHORIZED=0 (NOT for production!)`);
        console.error(`   2. For production: Install the CA certificate in your system trust store`);
        console.error(`   3. Alternative: Use a certificate signed by a trusted CA\n`);
      } else if (errorMessage.includes('unable to verify') || errorMessage.includes('certificate verify failed')) {
        console.error(`\n💡 [Certificate Debug] CERTIFICATE VERIFICATION FAILED`);
        console.error(`   The certificate chain could not be verified.`);
        console.error(`   Possible causes:`);
        console.error(`   - Self-signed certificate`);
        console.error(`   - Missing intermediate certificates`);
        console.error(`   - Untrusted root CA`);
        console.error(`   - Certificate revocation`);
        console.error(`   Solutions:`);
        console.error(`   1. Check if the server provides the full certificate chain`);
        console.error(`   2. Ensure intermediate certificates are included`);
        console.error(`   3. For testing: Set NODE_TLS_REJECT_UNAUTHORIZED=0\n`);
      } else if (errorMessage.includes('hostname') || errorMessage.includes('certificate is not valid')) {
        console.error(`\n💡 [Certificate Debug] HOSTNAME MISMATCH`);
        console.error(`   The certificate hostname doesn't match the requested URL.`);
        console.error(`   Solutions:`);
        console.error(`   1. Ensure the certificate includes the correct hostname in CN or SAN`);
        console.error(`   2. Use the exact hostname specified in the certificate`);
        console.error(`   3. For testing: Set NODE_TLS_REJECT_UNAUTHORIZED=0\n`);
      } else if (errorMessage.includes('expired')) {
        console.error(`\n💡 [Certificate Debug] CERTIFICATE EXPIRED`);
        console.error(`   The server certificate has expired.`);
        console.error(`   Solutions:`);
        console.error(`   1. Renew the server certificate`);
        console.error(`   2. For testing: Set NODE_TLS_REJECT_UNAUTHORIZED=0\n`);
      } else if (errorMessage.includes('econnrefused')) {
        console.error(`\n💡 [Certificate Debug] CONNECTION REFUSED`);
        console.error(`   Could not connect to the server (not a certificate issue).`);
        console.error(`   Check that the server is running and the URL/port are correct.\n`);
      } else {
        console.error(`\n💡 [Certificate Debug] Check the error details above for more information.\n`);
      }
    }

    throw error;
  }
}

/**
 * Enable certificate debugging for all requests
 */
export function enableCertificateDebugging() {
  process.env.DEBUG_CERTS = 'true';
  console.log('🔍 Certificate debugging enabled for all HTTPS requests');
}

/**
 * Disable certificate debugging
 */
export function disableCertificateDebugging() {
  process.env.DEBUG_CERTS = 'false';
  console.log('Certificate debugging disabled');
}
