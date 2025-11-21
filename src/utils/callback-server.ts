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

export interface CallbackServerHandle {
  waitForCallback: () => Promise<CallbackResult>;
  close: () => void;
}

/**
 * Start a local HTTP server to handle OAuth callback
 * Returns a promise that resolves when server is listening, with a handle to wait for callback
 */
export async function startCallbackServer(port: number): Promise<CallbackServerHandle> {
  return new Promise((resolveStart, rejectStart) => {
    let callbackResolve: (result: CallbackResult) => void;
    let callbackReject: (error: Error) => void;
    let timeoutId: NodeJS.Timeout;

    const callbackPromise = new Promise<CallbackResult>((resolve, reject) => {
      callbackResolve = resolve;
      callbackReject = reject;
    });

    const server = http.createServer((req, res) => {
      if (!req.url) {
        res.writeHead(400);
        res.end('Bad Request');
        return;
      }

      // Parse the callback URL
      const url = new URL(req.url, `http://localhost:${port}`);

      // Accept callback on both / and /callback paths
      if (url.pathname === '/callback' || url.pathname === '/') {
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
          callbackResolve({ error, error_description: errorDescription || undefined });
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
          callbackResolve({ code, state: state || undefined });
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

          callbackResolve({ error: 'invalid_response', error_description: 'No code or error in callback' });
        }

        // Close server after handling the callback
        clearTimeout(timeoutId);
        server.close();
      } else {
        // Handle other paths
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    // Handle server errors (e.g., port in use)
    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        rejectStart(new Error(`Port ${port} is already in use. Please choose a different callback port or close the application using it.`));
      } else {
        rejectStart(err);
      }
    });

    // Start listening
    server.listen(port, () => {
      console.log(`\nCallback server listening on http://localhost:${port}/callback`);

      // Timeout after 5 minutes
      timeoutId = setTimeout(() => {
        server.close();
        callbackReject(new Error('OAuth callback timeout - no response received within 5 minutes'));
      }, 5 * 60 * 1000);

      // Return handle to caller
      resolveStart({
        waitForCallback: () => callbackPromise,
        close: () => {
          clearTimeout(timeoutId);
          server.close();
        }
      });
    });
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
