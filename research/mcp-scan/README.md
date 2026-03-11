# MCP Config Scanner (T2-A)

This directory contains a standalone research pipeline for article T2-A:
**"We Scanned 10,000 MCP Server Configs. Here's What We Found."**

It searches GitHub for public MCP config files, parses server definitions, runs security checks, and produces aggregate article-ready statistics.

## Scope

Target files and patterns:
- `claude_desktop_config.json`
- `.cursor/mcp.json`
- `mcp.json`
- `.mcp.json`
- JSON files containing `mcpServers` or `mcp-servers`

## Structure

- `scan_github.py` - GitHub search + fetch + parse + check + JSONL output
- `analyze_configs.py` - aggregate analysis from downloaded dataset
- `aggregate_stats.py` - article-ready markdown stats and ASCII charts
- `lib/github_client.py` - GitHub code search client (stdlib only)
- `lib/config_parser.py` - MCP format parser
- `lib/security_checks.py` - check set MCP-001..MCP-013
- `data/` - raw anonymized dataset (`configs.jsonl`)
- `results/` - analysis outputs (`analysis.json`, `analysis.md`, `article_stats.md`)

## Dependencies

- Python 3.10+
- Stdlib only (no third-party package required)
- Optional but recommended: `GITHUB_TOKEN` environment variable

Without token, GitHub API limits are very low.

## Usage

```bash
python research/mcp-scan/scan_github.py --max-configs 20
python research/mcp-scan/analyze_configs.py
python research/mcp-scan/aggregate_stats.py
```

## Outputs

- `research/mcp-scan/data/configs.jsonl`
- `research/mcp-scan/results/analysis.json`
- `research/mcp-scan/results/analysis.md`
- `research/mcp-scan/results/article_stats.md`

## Privacy and Ethics

- Repository identities are hashed (`repo_hash`) before saving.
- No repository owner names or URLs are emitted in result artifacts.
- Secret-like values are redacted to pattern-only placeholders.
- Article output is aggregate-only; no repo call-outs.
