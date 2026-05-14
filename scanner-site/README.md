# MCP Security Scanner

Free online tool to check if your MCP server configuration is secure.

## Try it

Open `index.html` in any browser. No server needed.

## Deploy

### GitHub Pages (recommended)
1. Push `scanner-site/` to a repo.
2. Enable GitHub Pages in Settings -> Pages -> Source: main / docs.
3. Copy `scanner-site/` contents to `docs/`.

### Netlify / Vercel

Deploy the `scanner-site/` folder directly. No build step needed.

### Custom domain

Point `orchesis.dev` or `scanner.orchesis.dev` to your static deployment.

## What it checks

- Hardcoded credentials (API keys, tokens, passwords)
- Unencrypted HTTP connections to remote servers
- Shell metacharacters and command injection in args
- Shell interpreter usage (bash, sh, powershell)
- Path traversal patterns
- Known vulnerable MCP server packages
- Missing version pinning (npx, uvx, pipx)
- Overprivileged filesystem access
- Wildcard tool permissions
- Network exposure (0.0.0.0 binding)
- TLS/SSL verification disabled
- Missing server descriptions
- Disabled but present servers

## Privacy

All analysis runs 100% in the browser. No data is collected or transmitted.
Your MCP config never leaves your machine.

## Built by

[Orchesis](https://github.com/poushwell/orchesis) - Open-source AI agent security runtime.

