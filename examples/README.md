# MCP Security Scanner Examples

This directory contains practical examples for using the MCP Security Scanner.

## Files

### Safe Tools

**File**: `safe_tools.json`

Example of tools that pass security scanning:
- No dangerous operations
- Safe parameter names
- Proper schema definitions

```bash
mcp-scan examples/safe_tools.json
```

Expected: ✅ No issues found

### Dangerous Tools

**File**: `dangerous_tools.json`

Example of tools with security issues:
- Code execution capabilities
- Direct file system access
- Privilege escalation with sudo
- Credential parameters

```bash
mcp-scan examples/dangerous_tools.json
```

Expected: ❌ Multiple issues found

### Configuration Files

#### Strict Policy

**File**: `scan-strict.json`

Strict security configuration:
- Scans current directory recursively
- Enables secret detection
- Excludes deprecated and test tools
- Fails on high severity issues

Usage:
```bash
mcp-scan --config examples/scan-strict.json
```

#### YAML Configuration

**File**: `scan.yaml`

YAML format configuration:
- Same as `scan-strict.json` but in YAML format
- Easier to read and maintain
- Comments for documentation

Usage:
```bash
mcp-scan --config examples/scan.yaml
```

## Quick Start

1. **See safe tools pass**:
   ```bash
   mcp-scan examples/safe_tools.json
   ```

2. **See dangerous tools fail**:
   ```bash
   mcp-scan examples/dangerous_tools.json --fail-level high
   ```

3. **Use strict config**:
   ```bash
   mcp-scan --config examples/scan-strict.json
   ```

4. **Generate JSON report**:
   ```bash
   mcp-scan examples/safe_tools.json --format json --output report.json
   cat report.json
   ```

## Creating Your Own Examples

### Template: Safe Tool

```json
{
  "tools": [
    {
      "name": "my_tool",
      "description": "A safe tool",
      "inputSchema": {
        "type": "object",
        "properties": {
          "param": {
            "type": "string",
            "enum": ["option1", "option2"]
          }
        },
        "required": ["param"]
      }
    }
  ]
}
```

### Template: Configuration File

```json
{
  "target": ".",
  "secrets": true,
  "format": "json",
  "exclude": ["deprecated_*"],
  "fail_level": "high"
}
```

## Testing Against Examples

Run tests with examples:

```bash
# Test safe tools
pytest tests/ -v -k "safe" --tb=short

# Test dangerous patterns
pytest tests/ -v -k "dangerous" --tb=short

# All security tests
pytest tests/test_additional_rules.py -v
```

## Integration Examples

### With GitHub Actions

See `.github/workflows/mcp-security-scan.yml` for complete CI/CD integration.

### With Pre-Commit Hooks

The pre-commit hook automatically scans staged `tools.json` files:

```bash
# Install hook
python scripts/install-hook.py

# Make a commit with scanning enabled
git add tools.json
git commit -m "Add new tools"
```

### With Make

```makefile
.PHONY: scan-safe scan-dangerous scan-all

scan-safe:
	mcp-scan examples/safe_tools.json

scan-dangerous:
	mcp-scan examples/dangerous_tools.json || true

scan-all:
	mcp-scan examples/ --format json
```

## Customization Guide

### Add Custom Rules

Edit `src/scanner/analyzers/dangerous_ops.py`:

```python
DANGEROUS_PATTERNS = {
    "your_category": {
        "your_rule": {
            "pattern": "pattern_to_match",
            "cwe": "CWE-123",
            "severity": "high"
        }
    }
}
```

### Extend Exclusions

Create `scan.yaml`:

```yaml
exclude:
  - your_pattern_*
  - internal_*
  - deprecated_*
```

### Combine Multiple Configs

```bash
# Start with team config
mcp-scan --config team-scan.json \
  --exclude local_* \
  --format sarif
```
