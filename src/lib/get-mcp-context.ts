import { log } from "./get-mcp-logger.js"
import type { McpLogger } from "./get-mcp-logger.js"

export interface ApiContext {
    log: McpLogger
}

let context: ApiContext | undefined

export async function getMcpContext(): Promise<ApiContext> {
    if (context) {
        return context
    }

    context = { log }

    return context
}