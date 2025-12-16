import 'dotenv/config'
import { z } from 'zod'

const McpConfigSchema = z.object({
    name: z.string(),
    version: z.string().regex(/^(\d+)\.(\d+)\.(\d+)$/),
})

export type McpConfig = z.infer<typeof McpConfigSchema>

let config: McpConfig | undefined

export function getMcpConfig(): McpConfig {
    if (config) {
        return config
    }

    config = McpConfigSchema.parse({
        name: process.env.NAME ?? '@heyamiko/amikonet-signer',
        version: process.env.VERSION ?? '1.0.0',
    })
    return config
}