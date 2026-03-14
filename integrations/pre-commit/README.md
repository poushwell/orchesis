# Orchesis pre-commit hook

Add to your .pre-commit-config.yaml:

```yaml
repos:
  - repo: https://github.com/poushwell/orchesis
    rev: v0.1.0
    hooks:
      - id: orchesis-mcp-scan
```
