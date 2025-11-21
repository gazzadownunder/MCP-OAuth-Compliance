/**
 * Backend API Server for MCP Compliance Tester
 * Handles CORS issues by proxying requests to MCP servers
 */

import express, { Express, Request, Response } from 'express';
import cors from 'cors';
import { MCPComplianceTester } from '../compliance/compliance-tester.js';
import { ServerTestConfig } from '../types/compliance.js';
import { exec } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class ComplianceAPIServer {
  private app: Express;
  private port: number;
  private runningTests: Map<string, Promise<unknown>> = new Map();

  constructor(port: number = 3001) {
    this.port = port;
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware() {
    // Enable CORS for frontend
    this.app.use(cors({
      origin: '*', // In production, restrict to specific origin
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
    }));

    this.app.use(express.json());
    this.app.use(express.static(path.join(__dirname, '../../public')));
  }

  private setupRoutes() {
    // Health check
    this.app.get('/api/health', (_req: Request, res: Response) => {
      res.json({ status: 'ok', timestamp: new Date().toISOString() });
    });

    // Run compliance tests
    this.app.post('/api/test', async (req: Request, res: Response) => {
      try {
        const config: ServerTestConfig = req.body;

        if (!config.serverUrl) {
          res.status(400).json({ error: 'serverUrl is required' });
          return;
        }

        // Validate URL format
        try {
          new URL(config.serverUrl);
        } catch {
          res.status(400).json({ error: 'Invalid serverUrl format' });
          return;
        }

        const testId = `test-${Date.now()}`;

        // Run tests asynchronously
        const testPromise = this.runTests(config);
        this.runningTests.set(testId, testPromise);

        // Return test ID immediately
        res.json({ testId, message: 'Tests started' });

        // Clean up after completion
        testPromise.finally(() => {
          setTimeout(() => this.runningTests.delete(testId), 300000); // Keep for 5 minutes
        });
      } catch (error) {
        console.error('Error starting tests:', error);
        res.status(500).json({
          error: 'Failed to start tests',
          message: error instanceof Error ? error.message : String(error),
        });
      }
    });

    // Run tests and return results immediately (synchronous endpoint)
    this.app.post('/api/test/sync', async (req: Request, res: Response) => {
      try {
        const config: ServerTestConfig = req.body;

        if (!config.serverUrl) {
          res.status(400).json({ error: 'serverUrl is required' });
          return;
        }

        // Validate URL format
        try {
          new URL(config.serverUrl);
        } catch {
          res.status(400).json({ error: 'Invalid serverUrl format' });
          return;
        }

        const results = await this.runTests(config);
        res.json(results);
      } catch (error) {
        console.error('Error running tests:', error);
        res.status(500).json({
          error: 'Failed to run tests',
          message: error instanceof Error ? error.message : String(error),
        });
      }
    });

    // Rerun a single test
    this.app.post('/api/test/rerun/:testId', async (req: Request, res: Response) => {
      try {
        const testId = req.params.testId;
        const config: ServerTestConfig = req.body;

        if (!config.serverUrl) {
          res.status(400).json({ error: 'serverUrl is required' });
          return;
        }

        const tester = new MCPComplianceTester(config);
        const result = await tester.runSingleTest(testId);

        if (result) {
          res.json(result);
        } else {
          res.status(404).json({ error: 'Test not found' });
        }
      } catch (error) {
        console.error('Error rerunning test:', error);
        res.status(500).json({
          error: 'Failed to rerun test',
          message: error instanceof Error ? error.message : String(error),
        });
      }
    });

    // Get test status
    this.app.get('/api/test/:testId', (req: Request, res: Response) => {
      const testId = req.params.testId;
      const test = this.runningTests.get(testId);

      if (!test) {
        res.status(404).json({ error: 'Test not found or expired' });
        return;
      }

      // Check if test is complete
      Promise.race([test, Promise.resolve('pending')])
        .then(result => {
          if (result === 'pending') {
            res.json({ status: 'running', testId });
          } else {
            res.json({ status: 'complete', testId, results: result });
          }
        })
        .catch(error => {
          res.status(500).json({
            status: 'error',
            testId,
            error: error instanceof Error ? error.message : String(error),
          });
        });
    });

    // Serve frontend (catch-all route for SPA)
    this.app.get('/', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../public/index.html'));
    });
  }

  private async runTests(config: ServerTestConfig) {
    const tester = new MCPComplianceTester(config);
    return await tester.runAllTests();
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.app.listen(this.port, () => {
        console.log(`\n🚀 MCP Compliance Tester API Server running on http://localhost:${this.port}`);
        console.log(`\n📊 Open http://localhost:${this.port} in your browser to use the compliance tester\n`);
        resolve();
      });
    });
  }

  async startAndOpenBrowser(): Promise<void> {
    await this.start();

    // Open browser after a short delay
    setTimeout(() => {
      const url = `http://localhost:${this.port}`;
      const platform = process.platform;

      let command: string;
      if (platform === 'win32') {
        command = `start ${url}`;
      } else if (platform === 'darwin') {
        command = `open ${url}`;
      } else {
        command = `xdg-open ${url}`;
      }

      exec(command, (error) => {
        if (error) {
          console.log(`\n💡 Please open ${url} in your browser manually\n`);
        }
      });
    }, 1000);
  }
}
