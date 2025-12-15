/**
 * Base authentication utilities and interfaces
 * Provides common structure for different DID authentication methods
 */

import { webcrypto } from 'node:crypto';

/**
 * Authentication strategy interface
 */
export interface AuthStrategy {
  /**
   * Get the provider name for this authentication strategy
   */
  getProvider(): string;

  /**
   * Sign a message using the strategy's signing method
   */
  signMessage(message: string, privateKey: string): string | Promise<string>;

  /**
   * Verify a signature using the strategy's verification method
   */
  verifySignature(
    message: string,
    signature: string,
    publicKeyOrAddress: string
  ): boolean | Promise<boolean>;

  /**
   * Convert an identifier (address/public key) to DID format
   */
  toDid(identifier: string, ...args: unknown[]): string;

  /**
   * Extract identifier from DID
   */
  fromDid(did: string): string;

  /**
   * Validate DID format
   */
  isValidDid(did: string): boolean;

  /**
   * Generate a random nonce
   */
  generateNonce(): string;
}

/**
 * Base class for authentication strategies
 */
export abstract class BaseAuthStrategy implements AuthStrategy {
  abstract getProvider(): string;
  abstract signMessage(message: string, privateKey: string): string | Promise<string>;
  abstract verifySignature(
    message: string,
    signature: string,
    publicKeyOrAddress: string
  ): boolean | Promise<boolean>;
  abstract toDid(identifier: string, ...args: unknown[]): string;
  abstract fromDid(did: string): string;
  abstract isValidDid(did: string): boolean;

  /**
   * Default nonce generation (can be overridden)
   */
  generateNonce(): string {
    const bytes = new Uint8Array(32);
    webcrypto.getRandomValues(bytes);
    return Buffer.from(bytes).toString('base64');
  }

  /**
   * Verify timestamp is within acceptable window
   */
  verifyTimestamp(timestamp: number, windowMs: number = 5 * 60 * 1000): boolean {
    const now = Date.now();
    
    // Check if timestamp is too old
    if (now - timestamp > windowMs) {
      return false;
    }
    
    // Check if timestamp is in the future (allow 60s clock skew)
    if (timestamp - now > 60 * 1000) {
      return false;
    }
    
    return true;
  }

  /**
   * Build authentication message
   */
  buildAuthMessage(did: string, timestamp: number, nonce: string): string {
    return `${did}:${timestamp}:${nonce}`;
  }
}

/**
 * Authentication request parameters
 */
export interface AuthRequest {
  did: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

/**
 * Authentication response
 */
export interface AuthResponse {
  success: boolean;
  token: string;
  userId: string;
  expiresIn: number;
}

/**
 * Nonce management for replay attack prevention
 */
export class NonceManager {
  private usedNonces: Map<string, number> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor(cleanupIntervalMs: number = 60 * 1000) {
    // Periodically clean up old nonces
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, cleanupIntervalMs);
  }

  /**
   * Check if nonce has been used
   */
  isUsed(nonce: string, timestamp: number): boolean {
    const existingTimestamp = this.usedNonces.get(nonce);
    
    if (existingTimestamp) {
      return true;
    }
    
    this.usedNonces.set(nonce, timestamp);
    return false;
  }

  /**
   * Clean up old nonces (older than 5 minutes)
   */
  cleanup(maxAgeMs: number = 5 * 60 * 1000): void {
    const now = Date.now();
    
    for (const [nonce, timestamp] of this.usedNonces.entries()) {
      if (now - timestamp > maxAgeMs) {
        this.usedNonces.delete(nonce);
      }
    }
  }

  /**
   * Stop cleanup interval
   */
  destroy(): void {
    clearInterval(this.cleanupInterval);
  }
}
