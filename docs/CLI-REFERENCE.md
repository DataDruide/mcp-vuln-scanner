# CLI Reference

## Command: `mcp-scan`

Security scanner for MCP (Model Context Protocol) tools and services.

```
mcp-scan [OPTIONS] TARGET
```

## Arguments

### TARGET
Path to tools.json file or directory to scan.

- **Type**: Path
- **Required**: Yes (if no config file provided)
- **Examples**:
  - `tools.json` - Single file
  - `.` - Current directory (recursive)
  - `src/tools/` - Specific directory

## Options

### `--config PATH`
Load configuration from file (JSON/YAML/TOML).

- **Type**: Path
- **Default**: None
- **Supported formats**:
  - `scan.json`
  - `scan.yaml` / `scan.yml`
  - `pyproject.toml` (under `[tool.mcp-security-scanner]`)
- **Example**:
  ```bash
  mcp-scan --config scan.json
  ```

### `--format FORMAT`
Output format for results.

- **Type**: String
- **Default**: `text` (human-readable)
- **Allowed values**:
  - `text` - Human-readable
  - `json` - Machine-readable JSON
  - `sarif` - Security Analysis Result Format (SARIF 2.1.0)
  - `html` - HTML report
- **Example**:
  ```bash
  mcp-scan tools.json --format sarif
  ```

### `--output PATH`
Write results to file instead of stdout.

- **Type**: Path
- **Default**: stdout
- **Example**:
  ```bash
  mcp-scan tools.json --output report.json
  ```

### `--secrets`
Enable secret detection in tool parameters.

- **Type**: Boolean flag
- **Default**: False
- **Detects**:
  - API keys
  - Database passwords
  - Tokens
  - Credentials
- **Example**:
  ```bash
  mcp-scan tools.json --secrets
  ```

### `--exclude PATTERN`
Exclude tools matching pattern (fnmatch style).

- **Type**: String (repeatable)
- **Default**: None
- **Pattern format**: Glob patterns
- **Examples**:
  ```bash
  # Exclude one pattern
  mcp-scan tools.json --exclude deprecated_*
  
  # Exclude multiple patterns
  mcp-scan tools.json --exclude deprecated_* --exclude test_*
  ```

### `--fail-level LEVEL`
Minimum severity to fail scan (non-zero exit code).

- **Type**: String
- **Default**: `high`
- **Allowed values**:
  - `critical` - Only fail on critical issues
  - `high` - Fail on high or critical
  - `medium` - Fail on medium, high, or critical
  - `low` - Fail on any issue
- **Example**:
  ```bash
  mcp-scan tools.json --fail-level critical
  ```

### `--ai-fix`
Generate AI-powered fix suggestions.

- **Type**: Boolean flag
- **Default**: False
- **Requirements**: 
  - OPENAI_API_KEY or ANTHROPIC_API_KEY environment variable
- **Example**:
  ```bash
  mcp-scan tools.json --ai-fix
  ```

### `--verbose, -v`
Increase verbosity level (can be repeated).

- **Type**: Boolean flag
- **Default**: False
- **Levels**:
  - `-v` - Verbose (show all findings)
  - `-vv` - Very verbose (show analysis steps)
  - `-vvv` - Debug (internal details)
- **Example**:
  ```bash
  mcp-scan tools.json -vv
  ```

### `--quiet, -q`
Suppress non-error output.

- **Type**: Boolean flag
- **Default**: False
- **Shows only**: Errors and final exit code
- **Example**:
  ```bash
  mcp-scan tools.json -q
  ```

### `--version`
Display version and exit.

- **Example**:
  ```bash
  mcp-scan --version
  ```

### `--help, -h`
Display help message and exit.

- **Example**:
  ```bash
  mcp-scan --help
  ```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan successful, no issues found |
| 1 | Scan successful, issues found matching fail-level |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | File not found |
| 5 | Scan error |

## Environment Variables

### AI Provider Configuration

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# Azure OpenAI
export AZURE_OPENAI_KEY="key..."
export AZURE_OPENAI_ENDPOINT="https://..."
```

### Scan Configuration

```bash
# Default config file location
export MCP_SCAN_CONFIG="scan.json"

# Default output format
export MCP_SCAN_FORMAT="json"
```

## Examples

### Example 1: Basic Scan

```bash
mcp-scan tools.json
```

### Example 2: CI/CD with SARIF

```bash
mcp-scan tools.json \
  --format sarif \
  --output sarif-report.sarif \
  --secrets \
  --fail-level high
```

### Example 3: Directory Scan with Exclusions

```bash
mcp-scan . \
  --exclude deprecated_* \
  --exclude test_* \
  --format json \
  --output results.json
```

### Example 4: AI-Powered Fixes

```bash
mcp-scan tools.json \
  --ai-fix \
  --format json \
  --output fixes.json
```

### Example 5: Verbose Debug

```bash
mcp-scan tools.json \
  --secrets \
  --fail-level critical \
  -vvv
```

## Configuration File Priority

When using configuration files, values are merged as follows (highest to lowest priority):

1. **Command-line arguments** - Explicitly provided flags
2. **Environment variables** - System environment settings
3. **Configuration file** - JSON/YAML/TOML file (--config)
4. **Defaults** - Built-in defaults

Example priority in action:

```bash
# scan.json has: { "format": "json", "secrets": false }

# This command:
mcp-scan tools.json --config scan.json --format sarif --secrets

# Effective settings:
# - format: sarif (from CLI, overrides config)
# - secrets: true (from CLI, overrides config)
# - target: tools.json (from CLI, required)
# - fail_level: high (from defaults)
```
