# Orchesis MCP Security Server

Security analysis tools for AI agent configurations. Works with Claude Desktop, Cursor, Claude Code, and any MCP client.

## Tools

| Tool | Description |
|------|-------------|
| `scan_mcp_config` | Scan MCP config JSON for security vulnerabilities (score 0-100) |
| `check_tool_call_safety` | Check if a specific tool call is safe before execution |
| `get_security_posture` | Get AI agent security best practices and threat landscape |

## Quick Setup

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "orchesis-security": {
      "command": "uvx",
      "args": ["orchesis-mcp-server"]
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "orchesis-security": {
      "command": "uvx",
      "args": ["orchesis-mcp-server"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add orchesis-security -- uvx orchesis-mcp-server
```

## Usage Examples

Ask Claude:

- "Scan my MCP config for security issues"
- "Is this tool call safe?"
- "What are the current security threats for AI agents?"

## Privacy

All analysis runs locally. No data is sent to external servers.

## Built by

[Orchesis](https://github.com/poushwell/orchesis) - Open-source AI agent control plane.
