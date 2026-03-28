# 🤖 AI-Powered Fixes

The MCP Vulnerability Scanner uses AI to automatically fix security issues.

## Quick Start with Ollama (Free)

```bash
# Install Ollama
brew install ollama
ollama serve &
ollama pull llama3.2

# Run AI fix
export AI_PROVIDER=ollama
export AI_MODEL=llama3.2
mcp-scan tools.json --fix --apply
