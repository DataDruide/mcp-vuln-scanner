# Installation Guide

## System Requirements

- Python 3.8 or higher
- pip package manager
- Git (for pre-commit hooks)

## Installation Methods

### Option 1: From Source (Development)

```bash
# Clone repository
git clone https://github.com/DataDruide/mcp-vuln-scanner.git
cd mcp-vuln-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Verify installation
mcp-scan --version
```

### Option 2: From PyPI (Production)

```bash
pip install mcp-security-scanner
mcp-scan --version
```

### Option 3: Docker

```bash
docker build -t mcp-security-scanner .
docker run -v $(pwd):/workspace mcp-security-scanner scan /workspace/tools.json
```

## Post-Installation Setup

### Install Pre-Commit Hook (Recommended)

The pre-commit hook prevents committing tools with critical security issues:

```bash
# From repository root
python scripts/install-hook.py
```

The hook will:
- Automatically run before each commit
- Scan staged `tools.json` files
- Block commits with critical issues
- Allow bypass with `git commit --no-verify` (not recommended)

### Configuration

Create a `scan.json`, `scan.yaml`, or `scan.yml` in your project:

```json
{
  "target": ".",
  "secrets": true,
  "format": "json",
  "exclude": ["deprecated_*", "test_*"],
  "ai_fix": false
}
```

Supported formats:
- **JSON**: `scan.json`
- **YAML**: `scan.yaml` or `scan.yml`
- **TOML**: `pyproject.toml` (under `[tool.mcp-security-scanner]`)

## Troubleshooting

### Command Not Found: `mcp-scan`

**Solution**: Ensure the virtual environment is activated:
```bash
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows
```

### Pre-Commit Hook Not Running

**Solution**: Reinstall the hook:
```bash
python scripts/install-hook.py
```

### Permission Denied (Docker)

**Solution**: Run with proper volume permissions:
```bash
docker run -v $(pwd):/workspace --user $(id -u):$(id -g) mcp-security-scanner scan /workspace/tools.json
```

### ModuleNotFoundError

**Solution**: Reinstall the package:
```bash
pip install -e . --force-reinstall
```

## Verification

After installation, verify everything works:

```bash
# Create test tools file
cat > test_tools.json << 'EOF'
{
  "tools": [
    {
      "name": "test_tool",
      "description": "A test tool",
      "inputSchema": {
        "properties": {
          "query": {"type": "string"}
        }
      }
    }
  ]
}
EOF

# Run scan
mcp-scan test_tools.json

# Cleanup
rm test_tools.json
```

Expected output:
```
Scanning 1 tools...
Found 0 dangerous operations
Found 0 secrets
✅ Scan completed successfully
```
