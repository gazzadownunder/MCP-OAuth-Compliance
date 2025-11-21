import http from 'http';
import { URL } from 'url';

/**
 * OAuth callback result
 */
export interface CallbackResult {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
}

/**
 * Start a local HTTP server to handle OAuth callback
 * Returns a promise that resolves with the authorization code
 */
export function startCallbackServer(port: number): Promise<CallbackResult> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      if (!req.url) {
        res.writeHead(400);
        res.end('Bad Request');
        return;
      }

      // Parse the callback URL
      const url = new URL(req.url, `http://localhost:${port}`);

      if (url.pathname === '/callback') {
        // Extract OAuth response parameters
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');
        const errorDescription = url.searchParams.get('error_description');

        // Send response to browser
        if (error) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
              <head><title>Authentication Error</title></head>
              <body>
                <h1>Authentication Failed</h1>
                <p><strong>Error:</strong> ${escapeHtml(error)}</p>
                ${errorDescription ? `<p><strong>Description:</strong> ${escapeHtml(errorDescription)}</p>` : ''}
                <p>You can close this window.</p>
              </body>
            </html>
          `);

          // Return error to caller
          resolve({ error, error_description: errorDescription || undefined });
        } else if (code) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
              <head><title>Authentication Successful</title></head>
              <body>
                <h1>Authentication Successful!</h1>
                <p>You have successfully authenticated. You can close this window.</p>
                <script>window.close();</script>
              </body>
            </html>
          `);

          // Return authorization code to caller
          resolve({ code, state: state || undefined });
        } else {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
              <head><title>Invalid Response</title></head>
              <body>
                <h1>Invalid Response</h1>
                <p>No authorization code or error received.</p>
                <p>You can close this window.</p>
              </body>
            </html>
          `);

          resolve({ error: 'invalid_response', error_description: 'No code or error in callback' });
        }

        // Close server after handling the callback
        server.close();
      } else {
        // Handle other paths
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    // Start listening
    server.listen(port, () => {
      console.log(`\nCallback server listening on http://localhost:${port}/callback`);
    });

    // Handle server errors
    server.on('error', (err) => {
      reject(err);
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      server.close();
      reject(new Error('OAuth callback timeout - no response received within 5 minutes'));
    }, 5 * 60 * 1000);
  });
}

/**
 * Simple HTML escape to prevent XSS in error messages
 */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
