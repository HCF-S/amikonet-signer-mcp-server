/**
 * Solana Cryptographic Utilities
 * For signing and verifying messages with Solana wallets
 * Implements did:pkh standard according to https://github.com/w3c-ccg/did-pkh
 */

import nacl from 'tweetnacl';
import bs58 from 'bs58';

/**
 * Solana mainnet chain ID according to CAIP-2
 * Format: solana:{genesisHash first 32 chars}
 */
const SOLANA_MAINNET_CHAIN_ID = 'solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ';

/**
 * Convert Solana wallet address to did:pkh format
 * According to did:pkh specification and CAIP-10
 * @param walletAddress - Base58 encoded Solana address
 * @param chainId - Optional chain ID (defaults to mainnet)
 * @returns DID in format did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:{address}
 */
export function walletAddressToDid(
  walletAddress: string,
  chainId: string = SOLANA_MAINNET_CHAIN_ID
): string {
  if (!isValidSolanaAddress(walletAddress)) {
    throw new Error('Invalid Solana wallet address');
  }
  return `did:pkh:${chainId}:${walletAddress}`;
}

/**
 * Extract wallet address from did:pkh DID
 * @param did - DID in format did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:{address}
 * @returns Solana wallet address
 */
export function didToWalletAddress(did: string): string {
  if (!did.startsWith('did:pkh:solana:')) {
    throw new Error('Invalid Solana did:pkh format');
  }
  
  const parts = did.split(':');
  if (parts.length !== 5) {
    throw new Error('Invalid did:pkh format. Expected did:pkh:solana:chainId:address');
  }
  
  const address = parts[4];
  if (!isValidSolanaAddress(address)) {
    throw new Error('Invalid Solana address in DID');
  }
  
  return address;
}

/**
 * Validate did:pkh format for Solana
 * @param did - DID to validate
 * @returns True if valid Solana did:pkh
 */
export function isValidSolanaDid(did: string): boolean {
  try {
    const address = didToWalletAddress(did);
    return isValidSolanaAddress(address);
  } catch {
    return false;
  }
}

/**
 * Sign a message with a Solana keypair
 * @param message - Message to sign
 * @param privateKeyBase58 - Private key in base58 format (64 bytes)
 * @returns Signature in base58 format
 */
export function signSolanaMessage(
  message: string,
  privateKeyBase58: string
): string {
  const messageBytes = new TextEncoder().encode(message);
  const privateKeyBytes = bs58.decode(privateKeyBase58);
  
  if (privateKeyBytes.length !== 64) {
    throw new Error('Invalid private key length. Expected 64 bytes for Solana keypair.');
  }
  
  const signature = nacl.sign.detached(messageBytes, privateKeyBytes);
  return bs58.encode(signature);
}

/**
 * Verify a Solana signature
 * @param message - Original message
 * @param signatureBase58 - Signature in base58 format
 * @param publicKeyBase58 - Public key in base58 format (32 bytes)
 * @returns True if signature is valid
 */
export function verifySolanaSignature(
  message: string,
  signatureBase58: string,
  publicKeyBase58: string
): boolean {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = bs58.decode(signatureBase58);
    const publicKeyBytes = bs58.decode(publicKeyBase58);
    
    if (publicKeyBytes.length !== 32) {
      throw new Error('Invalid public key length. Expected 32 bytes.');
    }
    
    if (signatureBytes.length !== 64) {
      throw new Error('Invalid signature length. Expected 64 bytes.');
    }
    
    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch (error) {
    console.error('Solana signature verification error:', error);
    return false;
  }
}

/**
 * Get Solana address from public key
 * @param publicKeyBase58 - Public key in base58 format
 * @returns Solana address
 */
export function getAddressFromPublicKeyBase58(publicKeyBase58: string): string {
  try {
    const publicKeyBytes = bs58.decode(publicKeyBase58);
    
    if (publicKeyBytes.length !== 32) {
      throw new Error('Invalid public key length. Expected 32 bytes.');
    }
    
    return publicKeyBase58;
  } catch (error) {
    throw new Error(`Failed to get address from public key: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Validate Solana address format
 * @param address - Address to validate
 * @returns True if valid Solana address
 */
export function isValidSolanaAddress(address: string): boolean {
  try {
    const decoded = bs58.decode(address);
    return decoded.length === 32;
  } catch {
    return false;
  }
}

/**
 * Generate a random nonce for Solana authentication
 * @returns Base58-encoded random nonce
 */
export function generateSolanaNonce(): string {
  const bytes = nacl.randomBytes(32);
  return bs58.encode(bytes);
}

/**
 * Extract public key bytes from Solana keypair
 * @param keypairBase58 - Full keypair in base58 format (64 bytes)
 * @returns Public key in base58 format (32 bytes)
 */
export function extractPublicKey(keypairBase58: string): string {
  const keypairBytes = bs58.decode(keypairBase58);
  
  if (keypairBytes.length !== 64) {
    throw new Error('Invalid keypair length. Expected 64 bytes.');
  }
  
  const publicKeyBytes = keypairBytes.slice(32);
  return bs58.encode(publicKeyBytes);
}
