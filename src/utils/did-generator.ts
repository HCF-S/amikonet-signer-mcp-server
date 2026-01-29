import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

ed25519.hashes.sha512 = sha512;
ed25519.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));

export type DidKeyPair = {
  did: string;
  privateKeyHex: string;
  publicKeyHex: string;
};

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function bytesToBase58(bytes: Uint8Array): string {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  let num = BigInt('0x' + bytesToHex(bytes));
  let result = '';

  while (num > 0n) {
    const remainder = num % 58n;
    result = ALPHABET[Number(remainder)] + result;
    num = num / 58n;
  }

  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    result = '1' + result;
  }

  return result;
}

function createDidKey(publicKeyBytes: Uint8Array): string {
  const prefix = new Uint8Array([0xed, 0x01]);
  const prefixedKey = new Uint8Array(prefix.length + publicKeyBytes.length);
  prefixedKey.set(prefix);
  prefixedKey.set(publicKeyBytes, prefix.length);

  const base58Key = bytesToBase58(prefixedKey);
  return `did:key:z${base58Key}`;
}

export async function generateDidKeyPair(): Promise<DidKeyPair> {
  const privateKey = ed25519.utils.randomSecretKey();
  const privateKeyHex = bytesToHex(privateKey);

  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  const publicKeyHex = bytesToHex(publicKey);

  const did = createDidKey(publicKey);

  return { did, privateKeyHex, publicKeyHex };
}

export function formatDidEnv(pair: DidKeyPair): string {
  return `AGENT_DID=${pair.did}\nAGENT_PRIVATE_KEY=${pair.privateKeyHex}\n`;
}
