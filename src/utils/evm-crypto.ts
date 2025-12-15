/**
 * EVM (Ethereum) DID cryptographic utilities
 * Supports did:ethr and did:pkh:eip155 formats
 */

import { ethers } from 'ethers';
import { webcrypto } from 'node:crypto';

/**
 * Sign a message with an EVM private key
 * @param message - Message to sign
 * @param privateKeyHex - Private key in hex format (with or without 0x prefix)
 * @returns Signature in hex format
 */
export function signEvmMessage(message: string, privateKeyHex: string): string {
  // Ensure private key has 0x prefix
  const privateKey = privateKeyHex.startsWith('0x') ? privateKeyHex : `0x${privateKeyHex}`;
  
  const wallet = new ethers.Wallet(privateKey);
  
  // Sign the message (this will hash it and sign)
  const signature = wallet.signingKey.sign(ethers.hashMessage(message)).serialized;
  
  return signature;
}

/**
 * Verify an EVM signature
 * @param message - Original message
 * @param signature - Signature in hex format
 * @param expectedAddress - Expected ethereum address (with or without 0x prefix)
 * @returns True if signature is valid and matches the address
 */
export function verifyEvmSignature(
  message: string,
  signature: string,
  expectedAddress: string
): boolean {
  try {
    // Recover the address from the signature
    const recoveredAddress = ethers.verifyMessage(message, signature);
    
    // Normalize addresses to lowercase for comparison
    const normalizedExpected = expectedAddress.toLowerCase();
    const normalizedRecovered = recoveredAddress.toLowerCase();
    
    return normalizedExpected === normalizedRecovered;
  } catch (error) {
    console.error('EVM signature verification error:', error);
    return false;
  }
}

/**
 * Convert an Ethereum address to did:ethr format
 * @param address - Ethereum address (with or without 0x prefix)
 * @param chainId - Optional chain ID (defaults to mainnet = 1)
 * @param network - Optional network name (e.g., 'mainnet', 'goerli', 'sepolia')
 * @returns DID in format did:ethr:[network:]address or did:ethr:[chainId:]address
 */
export function addressToEthrDid(
  address: string,
  chainId?: number | string,
  network?: string
): string {
  // Normalize address
  const normalizedAddress = address.toLowerCase().startsWith('0x') 
    ? address.toLowerCase() 
    : `0x${address.toLowerCase()}`;

  // Validate address format
  if (!ethers.isAddress(normalizedAddress)) {
    throw new Error('Invalid Ethereum address');
  }

  // Build DID
  if (network && network !== 'mainnet') {
    return `did:ethr:${network}:${normalizedAddress}`;
  } else if (chainId && chainId !== 1 && chainId !== '0x1') {
    // Convert chainId to hex if it's a number
    const hexChainId = typeof chainId === 'number' 
      ? `0x${chainId.toString(16)}` 
      : chainId;
    return `did:ethr:${hexChainId}:${normalizedAddress}`;
  }
  
  // Default mainnet
  return `did:ethr:${normalizedAddress}`;
}

/**
 * Convert an Ethereum address to did:pkh:eip155 format
 * @param address - Ethereum address (with or without 0x prefix)
 * @param chainId - Chain ID (defaults to 1 for mainnet)
 * @returns DID in format did:pkh:eip155:chainId:address
 */
export function addressToPkhDid(address: string, chainId: number = 1): string {
  // Normalize address
  const normalizedAddress = address.toLowerCase().startsWith('0x') 
    ? address.toLowerCase() 
    : `0x${address.toLowerCase()}`;

  // Validate address format
  if (!ethers.isAddress(normalizedAddress)) {
    throw new Error('Invalid Ethereum address');
  }

  return `did:pkh:eip155:${chainId}:${normalizedAddress}`;
}

/**
 * Extract Ethereum address from did:ethr or did:pkh:eip155 DID
 * @param did - DID string
 * @returns Ethereum address (lowercase with 0x prefix)
 */
export function didToAddress(did: string): string {
  if (did.startsWith('did:ethr:')) {
    // Format: did:ethr:address or did:ethr:network:address or did:ethr:chainId:address
    const parts = did.split(':');
    
    if (parts.length === 3) {
      // did:ethr:address
      return parts[2].toLowerCase();
    } else if (parts.length === 4) {
      // did:ethr:network:address or did:ethr:chainId:address
      return parts[3].toLowerCase();
    }
    
    throw new Error('Invalid did:ethr format');
  } else if (did.startsWith('did:pkh:eip155:')) {
    // Format: did:pkh:eip155:chainId:address
    const parts = did.split(':');
    
    if (parts.length !== 5) {
      throw new Error('Invalid did:pkh:eip155 format. Expected did:pkh:eip155:chainId:address');
    }
    
    return parts[4].toLowerCase();
  }
  
  throw new Error('Unsupported DID format. Expected did:ethr or did:pkh:eip155');
}

/**
 * Extract chain ID from did:ethr or did:pkh:eip155 DID
 * @param did - DID string
 * @returns Chain ID (number) or null if mainnet/not specified
 */
export function extractChainId(did: string): number | null {
  if (did.startsWith('did:ethr:')) {
    const parts = did.split(':');
    
    if (parts.length === 3) {
      // did:ethr:address - mainnet by default
      return 1;
    } else if (parts.length === 4) {
      const networkOrChainId = parts[2];
      
      // Check if it's a hex chain ID
      if (networkOrChainId.startsWith('0x')) {
        return parseInt(networkOrChainId, 16);
      }
      
      // Map common network names to chain IDs
      const networkMap: Record<string, number> = {
        'mainnet': 1,
        'goerli': 5,
        'sepolia': 11155111,
        'polygon': 137,
        'optimism': 10,
        'arbitrum': 42161,
      };
      
      return networkMap[networkOrChainId] || null;
    }
  } else if (did.startsWith('did:pkh:eip155:')) {
    const parts = did.split(':');
    
    if (parts.length === 5) {
      return parseInt(parts[3], 10);
    }
  }
  
  return null;
}

/**
 * Validate EVM DID format (did:ethr or did:pkh:eip155)
 * @param did - DID to validate
 * @returns True if valid
 */
export function isValidEvmDid(did: string): boolean {
  try {
    const address = didToAddress(did);
    return ethers.isAddress(address);
  } catch {
    return false;
  }
}

/**
 * Validate Ethereum address format
 * @param address - Address to validate
 * @returns True if valid
 */
export function isValidEvmAddress(address: string): boolean {
  try {
    return ethers.isAddress(address);
  } catch {
    return false;
  }
}

/**
 * Generate a random nonce for EVM authentication
 * @returns Base64-encoded random nonce
 */
export function generateEvmNonce(): string {
  const bytes = new Uint8Array(32);
  webcrypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString('base64');
}

/**
 * Generate a new EVM wallet (for testing/development)
 * @returns Object with address, privateKey, and did
 */
export function generateEvmWallet(): {
  address: string;
  privateKey: string;
  did: string;
  pkhDid: string;
} {
  const wallet = ethers.Wallet.createRandom();
  
  return {
    address: wallet.address.toLowerCase(),
    privateKey: wallet.privateKey,
    did: addressToEthrDid(wallet.address),
    pkhDid: addressToPkhDid(wallet.address),
  };
}

/**
 * Get public key from private key
 * @param privateKeyHex - Private key in hex format
 * @returns Public key (compressed) in hex format
 */
export function getPublicKeyFromPrivateKey(privateKeyHex: string): string {
  const privateKey = privateKeyHex.startsWith('0x') ? privateKeyHex : `0x${privateKeyHex}`;
  const wallet = new ethers.Wallet(privateKey);
  return wallet.signingKey.compressedPublicKey;
}
