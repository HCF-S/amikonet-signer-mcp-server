import { z } from 'zod'
import { signMessage, generateNonce } from '../utils/crypto'
import { signSolanaMessage } from '../utils/solana-crypto'
import { signEvmMessage } from '../utils/evm-crypto'
import { detectDidProvider, getCredentialsFromEnv, type DidProvider } from '../utils/did-helpers'
import { getMcpContext } from './get-mcp-context'

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
                    'Sign a message with your DID private key using credentials from environment variables. Returns a signature that can be sent to the AmikoNet MCP server for authentication. Private keys never leave this tool.',
                inputSchema: {
                    message: z.string().describe('Message to sign (typically an authentication challenge)'),
                    provider: z
                        .enum(['key', 'solana', 'evm'])
                        .optional()
                        .describe('DID provider (optional, auto-detected from environment)'),
                },
            },
            callback: async (args: {
                message: string
                provider?: DidProvider
            }) => {
                try {
                    const { message, provider: providedProvider } = args

                    const envCreds = getCredentialsFromEnv(providedProvider)

                    if (!envCreds) {
                        throw new Error('No credentials found in environment variables. Please set AGENT_DID and AGENT_PRIVATE_KEY (or provider-specific variants).')
                    }

                    const { did, privateKey, provider } = envCreds

                    let signature: string

                    if (provider === 'solana') {
                        signature = signSolanaMessage(message, privateKey)
                    } else if (provider === 'evm') {
                        signature = signEvmMessage(message, privateKey)
                    } else {
                        signature = await signMessage(message, privateKey)
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
                    'Generate a complete authentication payload with signature using credentials from environment variables. Returns { did, timestamp, nonce, signature } ready to send to amikonet_authenticate.',
                inputSchema: {
                    provider: z
                        .enum(['key', 'solana', 'evm'])
                        .optional()
                        .describe('DID provider (optional, auto-detected from environment)'),
                },
            },
            callback: async (args: { provider?: DidProvider }) => {
                try {
                    const { provider: providedProvider } = args

                    const envCreds = getCredentialsFromEnv(providedProvider)
                    
                    if (!envCreds) {
                        throw new Error('No credentials found in environment variables. Please set AGENT_DID and AGENT_PRIVATE_KEY (or provider-specific variants).')
                    }

                    const { did, privateKey, provider } = envCreds

                    const timestamp = Date.now()
                    const nonce = generateNonce()

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