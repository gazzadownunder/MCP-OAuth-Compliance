#!/usr/bin/env node
/**
 * MCP Authorization Flow Compliance Tester
 * Main entry point for the compliance testing tool
 */

import { ComplianceAPIServer } from './server/api-server.js';

function parseArgs(): { port: number } {
  const args = process.argv.slice(2);
  let port = process.env.PORT ? parseInt(process.env.PORT) : 3001;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' || args[i] === '-p') {
      const portArg = args[i + 1];
      if (portArg && !isNaN(parseInt(portArg))) {
        port = parseInt(portArg);
        i++;
      }
    } else if (args[i].startsWith('--port=')) {
      const portArg = args[i].split('=')[1];
      if (!isNaN(parseInt(portArg))) {
        port = parseInt(portArg);
      }
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log('Usage: mcp-oauth-compliance [options]');
      console.log('');
      console.log('Options:');
      console.log('  -p, --port <number>  Server port (default: 3001, or PORT env var)');
      console.log('  -h, --help           Show this help message');
      process.exit(0);
    }
  }

  return { port };
}

async function main() {
  console.log('🔐 MCP Authorization Flow Compliance Tester');
  console.log('=========================================\n');

  const { port } = parseArgs();

  try {
    const server = new ComplianceAPIServer(port);
    await server.startAndOpenBrowser();
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

main();
