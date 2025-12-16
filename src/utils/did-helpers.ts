import {
  isValidSolanaAddress,
  isValidSolanaDid,
} from './solana-crypto'
import {
  isValidEvmAddress,
  isValidEvmDid,
} from './evm-crypto'

export type DidProvider = 'key' | 'solana' | 'evm'

export function detectDidProvider(did: string): DidProvider {
  if (did.startsWith('did:key:')) {
    return 'key'
  } else if (did.startsWith('did:pkh:solana:')) {
    return 'solana'
  } else if (did.startsWith('did:ethr:') || did.startsWith('did:pkh:eip155:')) {
    return 'evm'
  }

  if (isValidSolanaAddress(did)) {
    return 'solana'
  } else if (isValidEvmAddress(did)) {
    return 'evm'
  }

  return 'key'
}

export function getCredentialsFromEnv(
  provider?: DidProvider,
): { did: string; privateKey: string; provider: DidProvider } | null {
  if (provider === 'solana' || !provider) {
    const solanaDid = process.env.AGENT_SOLANA_DID || process.env.AGENT_DID
    const solanaKey = process.env.AGENT_SOLANA_PRIVATE_KEY || process.env.AGENT_PRIVATE_KEY
    if (solanaDid && solanaKey && (isValidSolanaDid(solanaDid) || isValidSolanaAddress(solanaDid))) {
      return { did: solanaDid, privateKey: solanaKey, provider: 'solana' }
    }
  }

  if (provider === 'evm' || !provider) {
    const evmDid = process.env.AGENT_EVM_DID || process.env.AGENT_DID
    const evmKey = process.env.AGENT_EVM_PRIVATE_KEY || process.env.AGENT_PRIVATE_KEY
    if (evmDid && evmKey && (isValidEvmDid(evmDid) || isValidEvmAddress(evmDid))) {
      return { did: evmDid, privateKey: evmKey, provider: 'evm' }
    }
  }

  if (provider === 'key' || !provider) {
    const keyDid = process.env.AGENT_DID
    const keyPrivateKey = process.env.AGENT_PRIVATE_KEY
    if (keyDid && keyPrivateKey && keyDid.startsWith('did:key:')) {
      return { did: keyDid, privateKey: keyPrivateKey, provider: 'key' }
    }
  }

  return null
}
