# src/scanner/reporters/sarif_reporter.py
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any
from ..analyzers.dangerous_ops import Finding, RiskLevel

class SarifReporter:
    """Generiert SARIF-konforme Berichte für GitHub Code Scanning"""
    
    def generate(self, findings: Dict[str, List], score=None) -> str:
        """Erstellt einen SARIF-Bericht"""
        
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "MCP Security Scanner",
                        "version": "0.2.0",
                        "informationUri": "https://github.com/mcp-security-scanner",
                        "rules": self._create_rules(findings)
                    }
                },
                "results": self._create_results(findings),
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                }]
            }]
        }
        
        return json.dumps(sarif, indent=2)
    
    def _create_rules(self, findings: Dict) -> List[Dict]:
        """Erstellt SARIF-Regeln aus Findings"""
        rules = []
        seen = set()
        
        # Dangerous Operations Rules
        for finding in findings.get("dangerous", []):
            rule_id = f"MCP-{finding.category.upper().replace('_', '-')}"
            if rule_id not in seen:
                rules.append({
                    "id": rule_id,
                    "name": finding.category,
                    "shortDescription": {"text": finding.description[:100]},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": self._map_severity(finding.risk_level)},
                    "help": {"text": finding.remediation},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe_id.split('-')[-1]}.html" if finding.cwe_id else None
                })
                seen.add(rule_id)
        
        # Poisoning Rules
        if findings.get("poisoning"):
            rules.append({
                "id": "MCP-POISONING",
                "name": "Tool Poisoning",
                "shortDescription": {"text": "Verdacht auf Tool-Poisoning"},
                "fullDescription": {"text": "Erkennt Typosquatting, irreführende Beschreibungen und verdächtige Parameter"},
                "defaultConfiguration": {"level": "warning"},
                "help": {"text": "Überprüfe Tool-Namen auf Typosquatting und entferne irreführende Beschreibungen"}
            })
        
        return rules
    
    def _create_results(self, findings: Dict) -> List[Dict]:
        """Erstellt SARIF-Results aus Findings"""
        results = []
        
        for finding in findings.get("dangerous", []):
            results.append({
                "ruleId": f"MCP-{finding.category.upper().replace('_', '-')}",
                "level": self._map_severity(finding.risk_level),
                "message": {"text": finding.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location},
                        "region": {"startLine": 1}
                    }
                }],
                "properties": {
                    "tool_name": finding.tool_name,
                    "remediation": finding.remediation,
                    "cwe": finding.cwe_id
                }
            })
        
        for finding in findings.get("poisoning", []):
            results.append({
                "ruleId": "MCP-POISONING",
                "level": "warning",
                "message": {"text": finding.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.tool_name},
                        "region": {"startLine": 1}
                    }
                }],
                "properties": {
                    "poisoning_type": finding.poisoning_type,
                    "confidence": finding.confidence,
                    "suggested_alternative": finding.suggested_alternative
                }
            })
        
        return results
    
    def _map_severity(self, risk_level: RiskLevel) -> str:
        """Mappt RiskLevel auf SARIF-Level"""
        mapping = {
            RiskLevel.CRITICAL: "error",
            RiskLevel.HIGH: "error",
            RiskLevel.MEDIUM: "warning",
            RiskLevel.LOW: "note",
            RiskLevel.INFO: "note"
        }
        return mapping.get(risk_level, "warning")
