#!/usr/bin/env node
/**
 * amikonet-signer-mcp-server
 * Local DID signer for AmikoNet
 * 
 * Manages private keys and creates cryptographic signatures
 * Private keys NEVER leave this package - only signatures are returned
 * 
 * Security Model:
 * - stdio transport only (no network exposure)
 * - Private keys in environment variables
 * - Returns signatures to agent
 * - Agent sends signatures to amikonet-mcp for verification
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import dotenv from 'dotenv';
import { getCredentialsFromEnv } from './utils/did-helpers';
import { getMcpServer } from './lib/get-mcp-server';
import { getMcpContext } from './lib/get-mcp-context';
import { formatDidEnv, generateDidKeyPair } from './utils/did-generator';

const args = process.argv.slice(2);
if (args[0] === 'generate') {
  const pair = await generateDidKeyPair();
  process.stdout.write(formatDidEnv(pair));
  console.error('✅ Generated DID keypair');
  console.error(`   DID: ${pair.did}`);
  console.error(`   Public Key (hex): ${pair.publicKeyHex}`);
  console.error('   Private key was printed to stdout as AGENT_PRIVATE_KEY.');
  process.exit(0);
}

dotenv.config();

const context = await getMcpContext();

context.log.info('🔐 AmikoNet Signer starting...');
context.log.info('📍 Mode: Local signing only (stdio transport)');
context.log.info('🔒 Security: Private keys never leave this process\n');

const hasCredentials = getCredentialsFromEnv() !== null;

if (!hasCredentials) {
  context.log.error('❌ Error: No credentials found in environment variables');
  context.log.error('   Set AGENT_DID and AGENT_PRIVATE_KEY (or provider-specific variants)');
  context.log.error('   Example: AGENT_DID=did:key:z6Mk... AGENT_PRIVATE_KEY=...\n');
  process.exit(1);
}

const credentials = getCredentialsFromEnv();
context.log.info('✅ Credentials loaded from environment');
context.log.info(`   Provider: ${credentials?.provider}`);
context.log.info(`   DID: ${credentials?.did}\n`);

async function main() {
  const server = await getMcpServer()
  const transport = new StdioServerTransport();
  await server.connect(transport);

  context.log.info('✅ Signer ready on stdio');
  context.log.info('📋 Available tools:');
  context.log.info('   - create_did_signature: Sign messages with your DID');
  context.log.info('   - generate_auth_payload: Generate complete auth payload for AmikoNet');
  context.log.info('   - create_x402_payment: Create signed x402 payment headers for purchases');
  context.log.info('🔒 Private keys are secure - only signatures will be returned');
  context.log.info('🔐 Security: All signing happens locally, keys never leave this process\n');
}

main().catch((error) => {
  context.log.error('❌ Fatal error:', error);
  process.exit(1);
});
