#!/bin/bash
# MCP Vulnerability Scanner - Dokumentations-Generator

set -e

echo "📚 MCP Vulnerability Scanner - Dokumentation Generator"
echo "======================================================"
echo ""

# Farben
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Verzeichnis erstellen
mkdir -p docs/images
mkdir -p docs/screenshots

echo "📸 1/6 Generiere Screenshots..."

# Terminal Screenshot 1: Hilfe
echo "   📸 mcp-scan --help"
script -q /dev/null mcp-scan --help > docs/screenshots/help.txt 2>&1 || true

# Terminal Screenshot 2: Beispiel-Scan
echo "   📸 mcp-scan example"
script -q /dev/null bash -c "echo '{\"tools\":[{\"name\":\"test\",\"inputSchema\":{\"properties\":{\"cmd\":{\"type\":\"string\"}}}}]}' > /tmp/test.json; mcp-scan /tmp/test.json" > docs/screenshots/scan.txt 2>&1 || true

# Terminal Screenshot 3: AI-Fix
echo "   📸 mcp-scan test.json --fix --apply"
export AI_PROVIDER=ollama
export AI_MODEL=llama3.2
script -q /dev/null bash -c "echo '{\"tools\":[{\"name\":\"test\",\"inputSchema\":{\"properties\":{\"cmd\":{\"type\":\"string\"}}}}]}' > /tmp/fix.json; mcp-scan /tmp/fix.json --fix --apply" > docs/screenshots/fix.txt 2>&1 || true

# HTML Report Screenshot (falls möglich)
echo "   📸 HTML Report generieren"
mcp-scan /tmp/test.json --format html --output docs/screenshots/report.html 2>/dev/null || true

echo -e "${GREEN}✅ Screenshots generiert${NC}"
echo ""

echo "📝 2/6 Erstelle README.md..."

cat > README.md << 'README_EOF'
# 🔒 MCP Vulnerability Scanner

<div align="center">

![PyPI](https://img.shields.io/pypi/v/mcp-vuln-scanner)
![Python](https://img.shields.io/pypi/pyversions/mcp-vuln-scanner)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/DataDruide/mcp-vuln-scanner)

**AI-powered security scanner for MCP (Model Context Protocol) servers with automatic fixes**

[Installation](#installation) • [Quick Start](#quick-start) • [AI Fix](#ai-fix) • [Commands](#commands) • [Pricing](#pricing)

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Dangerous Operations** | Detect command injection, path traversal, SQL injection |
| 🎭 **Tool Poisoning** | Identify typosquatting, misleading descriptions |
| 🤖 **AI-Powered Fixes** | Automatic security fixes with Ollama (free/local), OpenAI, Gemini |
| 📊 **Multiple Formats** | Console, JSON, HTML (with charts), SARIF (GitHub) |
| 📢 **Integrations** | Slack, Jira, GitHub Actions, VS Code |
| 🌐 **Live Scanning** | Scan running MCP servers via HTTP/SSE |
| 🔐 **Pro/Enterprise** | Ready-to-use licensing system |

---

## 🚀 Installation

```bash
pip install mcp-vuln-scanner