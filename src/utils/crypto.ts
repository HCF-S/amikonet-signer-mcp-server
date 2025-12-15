/**
 * Cryptographic utilities for DID signing and verification
 */

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { webcrypto } from 'node:crypto';

// Set the hash function for ed25519
ed25519.hashes.sha512 = sha512;
ed25519.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));

/**
 * Sign a message with a private key
 * @param message - Message to sign
 * @param privateKeyHex - Private key in hex format
 * @returns Signature in hex format
 */
export async function signMessage(
  message: string,
  privateKeyHex: string
): Promise<string> {
  const messageBytes = new TextEncoder().encode(message);
  const privateKeyBytes = hexToBytes(privateKeyHex);
  
  const signature = await ed25519.signAsync(messageBytes, privateKeyBytes);
  return bytesToHex(signature);
}

/**
 * Verify a signature
 * @param message - Original message
 * @param signatureHex - Signature in hex format
 * @param publicKeyHex - Public key in hex format
 * @returns True if signature is valid
 */
export async function verifySignature(
  message: string,
  signatureHex: string,
  publicKeyHex: string
): Promise<boolean> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = hexToBytes(signatureHex);
    const publicKeyBytes = hexToBytes(publicKeyHex);
    
    return await ed25519.verifyAsync(signatureBytes, messageBytes, publicKeyBytes);
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

/**
 * Extract public key from did:key DID
 * @param did - DID in format did:key:z...
 * @returns Public key in hex format
 */
export function extractPublicKeyFromDID(did: string): string | null {
  if (!did.startsWith('did:key:z')) {
    return null;
  }
  
  // Remove 'did:key:z' prefix
  const multibaseKey = did.slice(8);
  
  // For Ed25519, the multibase encoding starts with '6Mk'
  // This is a simplified extraction - in production use proper multibase/multicodec libraries
  if (multibaseKey.startsWith('6Mk')) {
    // Base58 decode and extract the key
    // TODO: Use proper multibase library (@multiformats/multibase)
    // For now, return the multibase string as-is (placeholder)
    return multibaseKey;
  }
  
  return null;
}

/**
 * Generate a random nonce
 * @returns Base64-encoded random nonce
 */
export function generateNonce(): string {
  const bytes = new Uint8Array(32);
  webcrypto.getRandomValues(bytes);
  return bytesToBase64(bytes);
}

// Helper functions
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}
