# Threat Intelligence

## Overview

The MCP Security Scanner includes a built-in threat intelligence database that tracks known malicious, vulnerable, and suspicious MCP tools. This database enables rapid detection of tools that pose known security risks.

## Features

- **Known Threat Detection**: Identifies tools matching known threat signatures
- **Severity Classification**: Critical, High, Medium, Low threat levels
- **Category-Based Filtering**: Group threats by type (code execution, credential theft, supply chain, etc.)
- **Confidence Scoring**: Indicates match certainty (0.0 - 1.0)
- **CVE Tracking**: Links to Common Vulnerabilities and Exposures
- **Mitigation Guidance**: Actionable steps to remediate detected threats

## Using Threat Intelligence

### Enable Threat Database Checks

```bash
mcp-scan tools.json --threat-db
```

### In Configuration File

```yaml
target: .
secrets: true
threat_db: true
format: json
fail_level: high
```

### Example Output

```
🔍 Checking against threat intelligence database...
   ⚠️  Threat detected: Arbitrary Code Execution Tool (critical)
   ⚠️  Threat detected: Supply Chain Poisoning Vector (critical)
   📊 Threat DB: 8 known threats in database
```

## Threat Categories

### Critical Threats

| ID | Name | Category | Description |
|---|---|---|---|
| TI-2024-001 | Arbitrary Code Execution Tool | code_execution | Executes arbitrary Python/shell code |
| TI-2024-002 | Credential Theft Tool | credential_theft | Exfiltrates credentials and env vars |
| TI-2024-003 | Supply Chain Poisoning | supply_chain | Injects malicious code into dependencies |
| TI-2024-004 | Privilege Escalation Tool | privilege_escalation | Escalates privileges without authorization |
| TI-2024-005 | Data Exfiltration Tool | data_exfiltration | Extracts and transmits sensitive data |

### High Threats

| ID | Name | Category | Description |
|---|---|---|---|
| TI-2024-006 | Prompt Injection Vulnerability | prompt_injection | Allows prompt injection attacks |
| TI-2024-007 | Deprecated Legacy Tool | deprecated | End-of-life with known vulnerabilities |

### Medium Threats

| ID | Name | Category | Description |
|---|---|---|---|
| TI-2024-008 | Unverified Third-Party Tool | unverified | From untrusted source without security review |

## Database Location

The threat database is stored at:

```
data/threat_intelligence.json
```

Format:

```json
{
  "threats": [
    {
      "id": "TI-2024-001",
      "name": "Threat Name",
      "description": "Description",
      "severity": "critical",
      "category": "threat_category",
      "indicators": ["pattern1", "pattern2"],
      "cve_ids": ["CVE-2024-XXXXX"],
      "discovered_date": "2024-01-15",
      "last_updated": "2024-07-06",
      "mitigations": ["Mitigation step 1"],
      "references": ["https://..."]
    }
  ],
  "metadata": {
    "version": "1.0.0",
    "last_updated": "2024-07-06",
    "total_threats": 8
  }
}
```

## Programmatic Usage

### Check Single Tool

```python
from scanner.threat_db import ThreatIntelligenceDB

db = ThreatIntelligenceDB()

# Check tool by name
matches = db.check_tool("execute_code")
for match in matches:
    print(f"⚠️  {match.threat_name} - {match.severity}")
```

### Filter Threats

```python
# Get all critical threats
critical = db.list_threats(severity="critical")

# Get code execution threats
code_exec = db.list_threats(category="code_execution")

# Get specific threat details
threat = db.get_threat("TI-2024-001")
print(f"Mitigations: {threat.mitigations}")
```

### Get Statistics

```python
stats = db.get_statistics()
print(f"Total threats: {stats['total_threats']}")
print(f"By severity: {stats['by_severity']}")
print(f"By category: {stats['by_category']}")
```

## Updating the Database

### Add New Threat

```python
from scanner.threat_db import ThreatIntelligenceDB, ThreatSignature

threat = ThreatSignature(
    id="TI-2024-009",
    name="New Threat",
    description="Description of the threat",
    severity="high",
    category="new_category",
    indicators=["indicator1", "indicator2"],
    cve_ids=["CVE-2024-XXXXX"],
    discovered_date="2024-07-06",
    last_updated="2024-07-06",
    mitigations=["Mitigation 1"],
    references=["https://example.com"]
)

db = ThreatIntelligenceDB()
db.add_threat(threat)
db.export_threats(Path("data/threat_intelligence.json"))
```

### Manual Update

Edit `data/threat_intelligence.json` directly:

```bash
# Edit JSON file
nano data/threat_intelligence.json

# Verify changes
mcp-scan tools.json --threat-db -vv
```

## Integration with CI/CD

### GitHub Actions

```yaml
- name: MCP Security Scan with Threat Intelligence
  run: |
    mcp-scan tools.json \
      --threat-db \
      --format sarif \
      --output results.sarif \
      --secrets \
      --fail-level high
```

### Fail on Known Threats

```bash
# This will fail if any tools match known threats
mcp-scan tools.json --threat-db --fail-level critical
```

## Threat Matching Algorithm

### Name Matching

- Exact case-insensitive string matching
- Confidence: 0.9

### Definition Matching

- JSON schema analysis
- Pattern searching in tool definition
- Confidence: 0.6

### Manual Indicators

- Can include regex patterns
- Custom indicators per threat
- User-defined confidence

## Best Practices

1. **Keep Database Updated**: Regularly update threat signatures with new findings
2. **Review Matches**: False positives may occur - review each match
3. **Combine Checks**: Use threat DB alongside dangerous ops and secret detection
4. **Document Issues**: Report new threats to maintain collective database
5. **Version Control**: Track threat DB changes in git

## Limitations

- Pattern matching may produce false positives
- Threat DB is community-maintained (may lag behind new threats)
- Requires manual updates for new signatures
- Cannot detect unknown (zero-day) threats

## Future Enhancements

- [ ] Automatic threat DB updates from remote sources
- [ ] Machine learning-based threat classification
- [ ] Real-time threat intelligence feeds
- [ ] Threat severity scoring algorithm
- [ ] Automated response actions

## Reporting New Threats

To report a new threat:

1. Create issue in GitHub repository
2. Include threat details (name, indicators, severity, mitigations)
3. Provide references (CVE IDs, articles, blog posts)
4. Include sample tools that match the threat

## References

- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [CVE - Common Vulnerabilities and Exposures](https://www.cve.org/)
- [OWASP](https://owasp.org/)
- [MCP Security](https://modelcontextprotocol.io/)
