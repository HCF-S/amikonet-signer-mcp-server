import { z } from 'zod'
import { signMessage, generateNonce } from '../utils/crypto'
import { signSolanaMessage } from '../utils/solana-crypto'
import { signEvmMessage } from '../utils/evm-crypto'
import { detectDidProvider, getCredentialsFromEnv, type DidProvider } from '../utils/did-helpers'
import { getMcpContext } from './get-mcp-context'
import { exact } from '@heyamiko/x402/schemes'
import { createKeyPairSignerFromBytes } from '@solana/kit'
import bs58 from 'bs58'

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
        {
            name: 'create_x402_payment',
            config: {
                title: 'Create x402 Payment',
                description:
                    'Create a signed x402 payment header for purchasing items. Takes payment requirements from a 402 response and returns a signed X-PAYMENT header.',
                inputSchema: {
                    paymentRequirements: z.object({
                        scheme: z.string(),
                        network: z.string(),
                        maxAmountRequired: z.string(),
                        payTo: z.string(),
                        asset: z.string(),
                        resource: z.string(),
                        description: z.string().optional(),
                        mimeType: z.string().optional(),
                        maxTimeoutSeconds: z.number().optional(),
                        extra: z.record(z.any()).optional(),
                    }).describe('Payment requirements from 402 response'),
                    svmRpcUrl: z.string().optional().describe('Custom Solana RPC URL'),
                },
            },
            callback: async (args: {
                paymentRequirements: {
                    scheme: string
                    network: string
                    maxAmountRequired: string
                    payTo: string
                    asset: string
                    resource: string
                    description?: string
                    mimeType?: string
                    maxTimeoutSeconds?: number
                    extra?: Record<string, any>
                }
                svmRpcUrl?: string
            }) => {
                try {
                    const { paymentRequirements, svmRpcUrl } = args
                    
                    // Get Solana credentials
                    const envCreds = getCredentialsFromEnv('solana')
                    
                    if (!envCreds || envCreds.provider !== 'solana') {
                        throw new Error('Solana credentials required for x402 payments. Set AGENT_DID and AGENT_PRIVATE_KEY for a Solana wallet.')
                    }
                    
                    const { privateKey } = envCreds
                    
                    // Decode the base58 private key to bytes
                    const privateKeyBytes = bs58.decode(privateKey!)
                    
                    // Create a Solana signer from the private key
                    const signer = await createKeyPairSignerFromBytes(privateKeyBytes)
                    
                    context.log.info(`Creating x402 payment for network: ${paymentRequirements.network}`)
                    context.log.info(`Amount: ${paymentRequirements.maxAmountRequired} to ${paymentRequirements.payTo}`)
                    
                    // Create the payment header using x402
                    const paymentHeader = await exact.svm.createPaymentHeader(
                        signer,
                        1, // x402Version
                        paymentRequirements as any,
                        svmRpcUrl ? { svmConfig: { rpcUrl: svmRpcUrl } } : undefined
                    )
                    
                    return {
                        content: [
                            {
                                type: 'text',
                                text: JSON.stringify(
                                    {
                                        success: true,
                                        paymentHeader,
                                        network: paymentRequirements.network,
                                        amount: paymentRequirements.maxAmountRequired,
                                        payTo: paymentRequirements.payTo,
                                        message: 'Payment header created. Include as X-PAYMENT header in your request.',
                                    },
                                    null,
                                    2,
                                ),
                            },
                        ],
                    }
                } catch (err) {
                    context.log.error('Error in create_x402_payment tool', err)
                    return {
                        content: [
                            {
                                type: 'text',
                                text: JSON.stringify(
                                    {
                                        success: false,
                                        error: err instanceof Error ? err.message : String(err),
                                    },
                                    null,
                                    2,
                                ),
                            },
                        ],
                    }
                }
            }
        },

    ]

    return tools
}