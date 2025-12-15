import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { getMcpTools } from './get-mcp-tools.js'
import { getMcpContext } from './get-mcp-context.js'
import { getMcpConfig } from './get-mcp-config.js'

const mcpConfig = getMcpConfig()
const context = await getMcpContext()

export async function getMcpServer() {
    const server = new McpServer(
        {
            name: mcpConfig.name,
            version: mcpConfig.version,
        },
        {
            capabilities: {},
        },
    )

    const tools = getMcpTools()

    for (const t of tools) {
        try {
            server.registerTool(
                t.name,
                t.config,
                async (args) => {
                    const result = await t.callback(args);
                    return {
                        content: result.content.map(item => ({
                            ...item,
                            type: "text" as const,
                            text: item.text ?? String(item.data ?? "")
                        }))
                    };
                }
            );
        } catch (err) {
            context.log.error(`Failed to register tool ${t.name}`, err as Error)
            throw err
        }
    }

    return server
}