# Changelog

All notable changes to the MCP Vulnerability Scanner.

## [1.2.0] - 2026-03-28

### Added
- 🔑 **Secret Detection** – Find API keys, passwords, tokens in MCP tools
- 📧 **Email Reports** – Send HTML reports via email (SMTP support)
- 🎮 **Discord Integration** – Send findings to Discord channels
- 🎭 Enhanced tool poisoning detection patterns
- 📊 Improved console output with secret findings

### Changed
- Updated CLI help with new options (`--secrets`, `--email`, `--discord`)
- Better error handling for all integrations
- Optimized secret detection patterns

## [1.1.0] - 2026-03-28

### Added
- 🤖 **AI-powered fixes** with Ollama (local, free) support
- 🔧 **Automatic fix application** (`--fix --apply`)
- 📢 **Slack integration** (`--slack URL`)
- 📋 **Jira integration** (`--jira`)
- 🎭 Enhanced tool poisoning detection
- 📊 Improved HTML reports with charts

## [1.0.0] - 2026-03-28

### Added
- Initial release
- Dangerous operations detection
- Tool poisoning detection
- HTML, JSON, SARIF reports
- Live MCP server scanning
- Pro/Enterprise licensing system
- VS Code extension
- GitHub Actions
