import { z } from 'zod'
import { signMessage, generateNonce } from '../utils/crypto.js'
import { signSolanaMessage, generateSolanaNonce } from '../utils/solana-crypto.js'
import { signEvmMessage, generateEvmNonce } from '../utils/evm-crypto.js'
import { detectDidProvider, getCredentialsFromEnv, type DidProvider } from '../utils/did-helpers.js'
import { getMcpContext } from './get-mcp-context.js'

export interface ToolDefinition {
    name: string
    config: {
        title: string
        description: string
        inputSchema: Record<string, z.ZodTypeAny>
    }
    callback: (
        args: any,
    ) => Promise<{ content: Array<{ type: string; data?: string; mimeType?: string; text?: string }> }>
}

const context = await getMcpContext()

export function getMcpTools(): ToolDefinition[] {
    const tools: ToolDefinition[] = [
        {
            name: 'create_did_signature',
            config: {
                title: 'Create DID Signature',
                description:
                    'Sign a message with your DID private key. Returns a signature that can be sent to the AmikoNet MCP server for authentication. Private keys never leave this tool.',
                inputSchema: {
                    message: z.string().describe('Message to sign (typically an authentication challenge)'),
                    did: z
                        .string()
                        .optional()
                        .describe(
                            'DID to sign with (optional if set in environment). Supports did:key, did:pkh:solana, did:ethr, did:pkh:eip155',
                        ),
                    provider: z
                        .enum(['key', 'solana', 'evm'])
                        .optional()
                        .describe('DID provider (optional, auto-detected from DID format)'),
                },
            },
            callback: async (args: {
                message: string
                did?: string
                privateKey?: string
                provider?: DidProvider
            }) => {
                try {

                    const { message, did: providedDid, privateKey: providedKey, provider: providedProvider } = args

                    let did = providedDid
                    let privateKey = providedKey
                    let provider = providedProvider

                    if (!did || !privateKey) {
                        const envCreds = getCredentialsFromEnv(provider)
                        if (!envCreds) {
                            throw new Error('No DID or private key provided, and none found in environment variables')
                        }
                        did = did || envCreds.did
                        privateKey = privateKey || envCreds.privateKey
                        provider = provider || envCreds.provider
                    }

                    if (!provider) {
                        provider = detectDidProvider(did!)
                    }

                    let nonce: string
                    if (provider === 'solana') {
                        nonce = generateSolanaNonce()
                    } else if (provider === 'evm') {
                        nonce = generateEvmNonce()
                    } else {
                        nonce = generateNonce()
                    }

                    let signature: string

                    if (provider === 'solana') {
                        signature = signSolanaMessage(message, privateKey!)
                    } else if (provider === 'evm') {
                        signature = signEvmMessage(message, privateKey!)
                    } else {
                        signature = await signMessage(message, privateKey!)
                    }

                    return {
                        content: [
                            {
                                type: 'text',
                                text: JSON.stringify(
                                    {
                                        success: true,
                                        did,
                                        message,
                                        nonce,
                                        signature,
                                        provider,
                                    },
                                    null,
                                    2,
                                ),
                            },
                        ],
                    }
                } catch (err) {
                    context.log.error('Error in create_did_signature tool', err)
                    throw err
                }
            },
        },
        {
            name: 'generate_auth_payload',
            config: {
                title: 'Generate Auth Payload',
                description:
                    'Generate a complete authentication payload with signature. This is a convenience tool that combines message generation and signing. Returns { did, timestamp, nonce, signature } ready to send to amikonet_authenticate.',
                inputSchema: {
                    did: z.string().optional().describe('DID to authenticate with (optional if set in environment)'),
                    provider: z
                        .enum(['key', 'solana', 'evm'])
                        .optional()
                        .describe('DID provider (optional, auto-detected)'),
                },
            },
            callback: async (args: { did?: string; privateKey?: string; provider?: DidProvider }) => {
                try {

                    const { did: providedDid, privateKey: providedKey, provider: providedProvider } = args

                    let did = providedDid
                    let privateKey = providedKey
                    let provider = providedProvider

                    if (!did || !privateKey) {
                        const envCreds = getCredentialsFromEnv(provider)
                        if (!envCreds) {
                            throw new Error('No DID or private key provided, and none found in environment variables')
                        }
                        did = did || envCreds.did
                        privateKey = privateKey || envCreds.privateKey
                        provider = provider || envCreds.provider
                    }

                    if (!provider) {
                        provider = detectDidProvider(did!)
                    }

                    const timestamp = Date.now()
                    let nonce: string

                    if (provider === 'solana') {
                        nonce = generateSolanaNonce()
                    } else if (provider === 'evm') {
                        nonce = generateEvmNonce()
                    } else {
                        nonce = generateNonce()
                    }

                    const message = `${did}:${timestamp}:${nonce}`

                    let signature: string

                    if (provider === 'solana') {
                        signature = signSolanaMessage(message, privateKey!)
                    } else if (provider === 'evm') {
                        signature = signEvmMessage(message, privateKey!)
                    } else {
                        signature = await signMessage(message, privateKey!)
                    }

                    return {
                        content: [
                            {
                                type: 'text',
                                text: JSON.stringify(
                                    {
                                        success: true,
                                        did,
                                        timestamp,
                                        nonce,
                                        signature,
                                        provider,
                                        message: 'Authentication payload ready. Send these values to amikonet_authenticate tool.',
                                    },
                                    null,
                                    2,
                                ),
                            },
                        ],
                    }
                } catch (err) {
                    context.log.error('Error in generate_auth_payload tool', err)
                    throw err
                }
            }
        },

    ]

    return tools
}