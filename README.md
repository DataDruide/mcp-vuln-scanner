# MCP Security Scanner

A comprehensive security scanning tool for MCP (Model Context Protocol) tools and services. Identifies dangerous operations, security vulnerabilities, secrets, and compliance issues in tool definitions.

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Actions](https://github.com/DataDruide/mcp-vuln-scanner/workflows/Tests/badge.svg)](https://github.com/DataDruide/mcp-vuln-scanner/actions)

## Features

### 🔍 Core Scanning Capabilities

- **Dangerous Operations Detection**: Identifies code execution, file system access, privilege escalation, and more
- **Secret Detection**: Finds exposed API keys, tokens, passwords, and credentials
- **MCP-Specific Rules**: Detects prompt injection, tool delegation abuse, and supply chain attacks
- **Supply Chain Analysis**: Identifies dependency vulnerabilities and tool poisoning attempts
- **Configurable Policies**: JSON/YAML/TOML configuration files for team standards

### 🚀 Developer Experience

- **Pre-Commit Hooks**: Prevent risky tools from being committed
- **CI/CD Integration**: GitHub Actions workflow included, SARIF report generation
- **Multiple Formats**: Text, JSON, SARIF, HTML reporting
- **Directory Scanning**: Recursive scanning of entire codebases
- **Tool Exclusion**: Glob patterns to exclude specific tools or categories

### 🤖 AI-Powered Features

- **Automated Fix Suggestions**: AI recommendations for remediating issues
- **Context-Aware Analysis**: Understands tool purpose and legitimate edge cases
- **Learning System**: Improves suggestions based on usage patterns

### 📊 Enterprise Features

- **Policy Enforcement**: Organization-wide security standards
- **Compliance Reporting**: SARIF format for GitHub Code Scanning
- **Team Configuration**: Shared scan configurations across projects
- **Threshold Management**: Fail-level settings (critical/high/medium/low)

## Quick Start

### Installation

```bash
# From source (development)
git clone https://github.com/DataDruide/mcp-vuln-scanner.git
cd mcp-vuln-scanner
pip install -e .

# Or from PyPI (production)
pip install mcp-security-scanner
```

See [Installation Guide](docs/INSTALLATION.md) for detailed instructions.

### Basic Usage

```bash
# Scan a single file
mcp-scan tools.json

# Scan directory recursively
mcp-scan .

# Output as JSON
mcp-scan tools.json --format json > report.json

# Enable secret detection
mcp-scan tools.json --secrets

# Exclude specific tools
mcp-scan tools.json --exclude "deprecated_*" --exclude "test_*"
```

### Install Pre-Commit Hook

```bash
python scripts/install-hook.py
```

The hook will automatically:
- Run before each commit
- Scan staged `tools.json` files
- Block commits with critical issues
- Provide clear remediation guidance

## Documentation

- **[Installation Guide](docs/INSTALLATION.md)** - Setup and configuration
- **[Usage Guide](docs/USAGE.md)** - Common use cases and examples
- **[CLI Reference](docs/CLI-REFERENCE.md)** - Complete command reference
- **[Threat Intelligence](docs/THREAT-INTELLIGENCE.md)** - Known threats database
- **[Web Dashboard](docs/DASHBOARD.md)** - Real-time monitoring interface
- **[Examples](examples/)** - Practical examples and templates
- **[Contributing Guide](CONTRIBUTING.md)** - Development guidelines

## Examples

### Safe Tools

```bash
mcp-scan examples/safe_tools.json
```

See [examples/safe_tools.json](examples/safe_tools.json)

### Dangerous Tools

```bash
mcp-scan examples/dangerous_tools.json --fail-level high
```

See [examples/dangerous_tools.json](examples/dangerous_tools.json)

### Configuration Files

```bash
# JSON configuration
mcp-scan --config examples/scan-strict.json

# YAML configuration
mcp-scan --config examples/scan.yaml
```

## Key Commands

### Scanning

```bash
# Basic scan with progress
mcp-scan tools.json

# JSON output for processing
mcp-scan tools.json --format json --output report.json

# SARIF format for GitHub Code Scanning
mcp-scan tools.json --format sarif --output results.sarif

# Verbose output for debugging
mcp-scan tools.json -vv
```

### Configuration

```bash
# Create project configuration
cat > scan.yaml << 'EOF'
target: .
secrets: true
format: json
exclude:
  - deprecated_*
  - test_*
fail_level: high
EOF

# Use configuration
mcp-scan --config scan.yaml
```

### Pre-Commit Hook

```bash
# Install hook
python scripts/install-hook.py

# Make commits (hook runs automatically)
git add tools.json
git commit -m "Add new tools"

# View hook behavior
cat .git/hooks/pre-commit
```

### CI/CD Integration

```bash
# GitHub Actions (automatic via .github/workflows/mcp-security-scan.yml)
git push

# Or run manually in workflow
mcp-scan tools.json --format sarif --secrets --fail-level high
```

## Security Rules

### Dangerous Operations

| Category | Detection | CWE |
|----------|-----------|-----|
| System Commands | `subprocess`, `os.system`, `exec` | CWE-78 |
| File Access | `open`, `write`, `delete` on paths | CWE-434 |
| Network Access | `socket`, `urllib`, `requests` | CWE-926 |
| Code Execution | `eval`, `exec`, `compile` | CWE-95 |
| Prompt Injection | Unsafe string formatting | CWE-77 |
| Privilege Escalation | `sudo`, `run_as_admin` | CWE-250 |
| Tool Delegation | Calling other MCPs unsafely | CWE-441 |

### Secrets Detection

Finds:
- API keys (`api_key`, `apiKey`, `API_KEY`)
- Tokens (`token`, `auth_token`, `jwt`)
- Passwords (`password`, `pwd`, `secret`)
- Database credentials
- AWS keys and secrets
- Private SSH keys
- OAuth tokens

## Output Formats

### Text (Default)

```
Scanning 2 tools...

Tool: execute_command
  ⚠️  Dangerous: system_command (CWE-78)
     Pattern: subprocess, os.system detected
  
Tool: get_weather  
  ✅ Safe

Summary:
  Scanned: 2 tools
  Dangerous: 1
  Secrets: 0
  Safe: 1
```

### JSON

```json
{
  "tools": [
    {
      "name": "execute_command",
      "findings": [
        {
          "type": "dangerous",
          "category": "system_command",
          "cwe": "CWE-78",
          "message": "Subprocess or os.system detected"
        }
      ]
    }
  ],
  "summary": {
    "scanned": 2,
    "dangerous": 1,
    "secrets": 0,
    "safe": 1
  }
}
```

### SARIF

Standard format for GitHub Code Scanning and other security tools.

```bash
mcp-scan tools.json --format sarif --output results.sarif
```

## Configuration Files

### JSON Format

```json
{
  "target": ".",
  "secrets": true,
  "format": "json",
  "exclude": ["deprecated_*"],
  "fail_level": "high"
}
```

### YAML Format

```yaml
target: .
secrets: true
format: json
exclude:
  - deprecated_*
fail_level: high
```

### TOML Format

```toml
[tool.mcp-security-scanner]
target = "."
secrets = true
format = "json"
exclude = ["deprecated_*"]
fail_level = "high"
```

## Environment Variables

```bash
# API keys for AI features
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# Default configuration
export MCP_SCAN_CONFIG="scan.yaml"
export MCP_SCAN_FORMAT="json"
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_dangerous_ops.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

Current: **22 tests passing** ✅

## GitHub Actions

Automatic scanning is configured in `.github/workflows/mcp-security-scan.yml`:

- Triggers on push to main
- Generates SARIF reports
- Results appear in GitHub Code Scanning tab
- Configurable fail thresholds

## Common Issues

### Pre-Commit Hook Not Running

```bash
# Reinstall hook
python scripts/install-hook.py

# Verify permissions
ls -la .git/hooks/pre-commit
```

### No Tools Found

```bash
# Verify file path
mcp-scan ./tools.json

# Check JSON format
cat tools.json | python -m json.tool
```

### Large Directory Scans

```bash
# Use exclusions
mcp-scan . --exclude vendor/* --exclude node_modules/*

# Or specify target
mcp-scan src/mcp_tools/
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Coding standards
- Testing requirements
- Pull request process

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Support

- 📖 [Documentation](docs/)
- 💬 [GitHub Issues](https://github.com/DataDruide/mcp-vuln-scanner/issues)
- 📧 Contact: [Email Support]

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

## Security

This scanner identifies security issues in MCP tools. For security vulnerabilities in this scanner itself, please email security@example.com instead of using the issue tracker.

## Roadmap

Planned features:
- [ ] Web dashboard for scan results
- [ ] Threat intelligence database
- [ ] Custom rule engine
- [ ] Policy templates
- [ ] Team management interface
- [ ] Automated remediation
- [ ] Supply chain tracking

---

**Made with ❤️ for secure MCP deployment**
