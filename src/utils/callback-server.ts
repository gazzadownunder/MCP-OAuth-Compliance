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
 * If the requested port is in use, will automatically try ports +1, +2, +3, etc. up to 10 attempts
 *
 * @param port - The desired callback port
 * @param serverUrl - The URL of the server under test (to avoid port conflicts)
 */
export async function startCallbackServer(
  port: number,
  serverUrl?: string,
  additionalUrlsToAvoid?: string[]
): Promise<CallbackServerHandle & { actualPort: number }> {
  // Extract ports from URLs to avoid
  const portsToAvoid = new Set<number>();

  // Add main server port
  if (serverUrl) {
    try {
      const url = new URL(serverUrl);
      const serverPort = url.port ? parseInt(url.port) : (url.protocol === 'https:' ? 443 : 80);
      portsToAvoid.add(serverPort);
      console.log(`  Will avoid MCP server port: ${serverPort} (from ${serverUrl})`);
    } catch (err) {
      console.warn(`  Failed to parse server URL: ${serverUrl}`);
    }
  }

  // Add additional ports to avoid
  if (additionalUrlsToAvoid) {
    for (const urlStr of additionalUrlsToAvoid) {
      try {
        const url = new URL(urlStr);
        const portToAvoid = url.port ? parseInt(url.port) : (url.protocol === 'https:' ? 443 : 80);
        portsToAvoid.add(portToAvoid);
        console.log(`  Will avoid authorization server port: ${portToAvoid} (from ${urlStr})`);
      } catch (err) {
        console.warn(`  Failed to parse URL: ${urlStr}`);
      }
    }
  }

  if (portsToAvoid.size > 0) {
    console.log(`  Ports to avoid: ${Array.from(portsToAvoid).join(', ')}`);
  }

  // Try up to 20 ports starting from the requested port (increased from 10 to account for skipped ports)
  for (let attempt = 0; attempt < 20; attempt++) {
    const tryPort = port + attempt;

    // Skip if this port should be avoided
    if (portsToAvoid.has(tryPort)) {
      console.log(`⏭️  Skipping port ${tryPort} (in use by server under test)`);
      continue;
    }

    console.log(`  Trying port ${tryPort}...`);
    try {
      const handle = await tryPort_Internal(tryPort);
      if (attempt > 0) {
        console.log(`✅ Port ${port} was in use, using port ${tryPort} instead`);
      } else {
        console.log(`✅ Callback server started on port ${tryPort}`);
      }
      return { ...handle, actualPort: tryPort };
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      // If it's not EADDRINUSE, throw immediately
      if (error.code !== 'EADDRINUSE') {
        console.error(`❌ Error starting callback server on port ${tryPort}: ${error.message}`);
        throw err;
      }
      console.log(`  Port ${tryPort} is already in use, trying next port...`);
      // If this was the last attempt, throw
      if (attempt === 19) {
        const endPort = port + 19;
        const portRange = portsToAvoid.size > 0
          ? `${port}-${endPort} (excluding ports ${Array.from(portsToAvoid).join(', ')})`
          : `${port}-${endPort}`;
        throw new Error(
          `All attempted ports (${portRange}) are in use. Please close applications using these ports or specify a different callback port.`
        );
      }
      // Otherwise, try next port
      continue;
    }
  }

  // This should never be reached
  throw new Error(`Failed to start callback server on any port from ${port} to ${port + 19}`);
}

/**
 * Internal function to try starting server on a specific port
 */
function tryPort_Internal(port: number): Promise<CallbackServerHandle> {
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

          callbackResolve({
            error: 'invalid_response',
            error_description: 'No code or error in callback'
          });
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
      rejectStart(err);
    });

    // Start listening
    server.listen(port, () => {
      console.log(`\nCallback server listening on http://localhost:${port}/callback`);

      // Timeout after 5 minutes
      timeoutId = setTimeout(
        () => {
          server.close();
          callbackReject(
            new Error('OAuth callback timeout - no response received within 5 minutes')
          );
        },
        5 * 60 * 1000
      );

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
