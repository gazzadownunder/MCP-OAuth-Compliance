#!/usr/bin/env node
/**
 * MCP Authorization Flow Compliance Tester
 * Main entry point for the compliance testing tool
 */

import { ComplianceAPIServer } from './server/api-server.js';

async function main() {
  console.log('🔐 MCP Authorization Flow Compliance Tester');
  console.log('=========================================\n');

  const port = process.env.PORT ? parseInt(process.env.PORT) : 8081;

  try {
    const server = new ComplianceAPIServer(port);
    await server.startAndOpenBrowser();
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

main();
