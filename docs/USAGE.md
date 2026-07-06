# Usage Guide

## Quick Start

### Basic Scan

```bash
mcp-scan tools.json
```

### Scan with JSON Output

```bash
mcp-scan tools.json --format json > report.json
```

### Scan Entire Directory

```bash
mcp-scan . --format sarif
```

### Enable Secret Detection

```bash
mcp-scan tools.json --secrets
```

### Exclude Specific Tools

```bash
mcp-scan tools.json --exclude "deprecated_*" --exclude "test_*"
```

## Configuration File Usage

### Using Scan Configuration

Instead of command-line flags, create `scan.json`:

```json
{
  "target": "tools",
  "secrets": true,
  "format": "json",
  "exclude": ["deprecated_*", "legacy_*"],
  "ai_fix": false,
  "fail_level": "high"
}
```

Then simply run:
```bash
mcp-scan --config scan.json
```

### Override Configuration with CLI

Configuration file values can be overridden on the command line:

```bash
# Config file has format: "json"
# Command line overrides it to "sarif"
mcp-scan --config scan.json --format sarif
```

Priority:
1. Command-line arguments (highest priority)
2. Configuration file values
3. Default values (lowest priority)

## Common Use Cases

### 1. CI/CD Integration (GitHub Actions)

Already configured in `.github/workflows/mcp-security-scan.yml`:

```yaml
- name: Run MCP Security Scan
  run: mcp-scan tools.json --format sarif --secrets --fail-level high
```

Results are automatically uploaded to GitHub Security tab.

### 2. Local Development with Pre-Commit Hook

Install once:
```bash
python scripts/install-hook.py
```

The hook automatically:
- Runs before every commit
- Scans staged `tools.json` files
- Blocks commits with critical issues
- Shows clear error messages with remediation steps

### 3. Batch Scanning Multiple Directories

```bash
# Scan current directory recursively for all tools.json files
mcp-scan . --format json --output results/

# Only scan specific directory
mcp-scan src/mcp_tools/ --format sarif
```

### 4. Fixing Issues with AI

```bash
# Generate AI-powered fix suggestions
mcp-scan tools.json --ai-fix --format json
```

The output includes suggested fixes for detected issues.

### 5. Strict Security Policy

```bash
# Fail on any security issue (even warnings)
mcp-scan tools.json --fail-level critical --secrets
```

### 6. Team-Wide Security Scanning

Create team configuration in repository root:

```yaml
# scan.yaml
target: .
secrets: true
format: sarif
fail_level: high
exclude:
  - deprecated_*
  - internal_*
ai_fix: false
```

All team members use:
```bash
mcp-scan --config scan.yaml
```

## Output Formats

### JSON Format

```bash
mcp-scan tools.json --format json
```

Output includes:
- Tool details with findings
- Summary with counts
- Detailed vulnerability information

### SARIF Format (Security Analysis Result Format)

```bash
mcp-scan tools.json --format sarif
```

- Standard format for GitHub Code Scanning
- Integrates with VS Code security views
- Machine-readable for automated processing

### Human-Readable Format (Default)

```bash
mcp-scan tools.json
```

Shows:
- Scan progress
- Found issues with explanations
- Summary statistics

## Advanced Options

### Custom Fail Levels

```bash
# Stop on critical issues only
mcp-scan tools.json --fail-level critical

# Stop on high severity
mcp-scan tools.json --fail-level high

# Stop on medium severity (strict)
mcp-scan tools.json --fail-level medium
```

### Verbose Output

```bash
mcp-scan tools.json -vv
```

Shows:
- All scanned tools
- Detailed analysis steps
- Rule matching information

### Quiet Mode

```bash
mcp-scan tools.json -q
```

Only shows:
- Critical issues
- Exit code

## Troubleshooting

### "No tools found"

**Problem**: Scan completes but reports no tools

**Solution**: 
- Check file path: `mcp-scan ./tools.json`
- Verify JSON format is valid
- Check tool files are named correctly

### "Permission denied" on pre-commit hook

**Problem**: Pre-commit hook doesn't run

**Solution**:
```bash
# Reinstall hook
python scripts/install-hook.py

# Or manually fix permissions
chmod +x .git/hooks/pre-commit
```

### Large file scanning is slow

**Problem**: Directory scan takes too long

**Solution**:
- Use `--exclude` to skip unneeded directories
- Create `scan.json` with specific target
- Run scan on CI/CD instead of every commit

## Integration Examples

### With Make

```makefile
.PHONY: security-scan
security-scan:
	mcp-scan tools.json --format sarif --secrets
```

### With npm

```json
{
  "scripts": {
    "security-scan": "mcp-scan tools.json --format json",
    "security-check": "mcp-scan . --fail-level high"
  }
}
```

### With tox

```ini
[testenv:security]
commands = mcp-scan tools.json --secrets --fail-level high
```
