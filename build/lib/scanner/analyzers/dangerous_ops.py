from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Any
import re


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    tool_name: str
    risk_level: RiskLevel
    category: str
    description: str
    location: str
    remediation: str
    cwe_id: str = None


class DangerousOperationAnalyzer:
    """Erkennt Tools mit gefährlichen Operationen"""

    DANGEROUS_PATTERNS = {
        "system_command": {
            "patterns": [
                r"subprocess\.(run|call|Popen)",
                r"os\.system",
                r"exec\(|eval\(",
                r"shell=True",
            ],
            "risk": RiskLevel.CRITICAL,
            "cwe": "CWE-78",
            "remediation": "Verwende parametrisierte APIs, validiere Eingaben"
        },
        "file_access": {
            "patterns": [
                r"open\([^)]*['\"]w",
                r"Path\.write",
                r"delete|remove|unlink",
            ],
            "risk": RiskLevel.HIGH,
            "cwe": "CWE-73",
            "remediation": "Implementiere Pfad-Whitelisting"
        },
        "network_access": {
            "patterns": [
                r"requests\.(get|post)",
                r"urllib\.request",
                r"fetch\(",
            ],
            "risk": RiskLevel.MEDIUM,
            "cwe": "CWE-918",
            "remediation": "Whiteliste erlaubte Domains"
        }
    }

    def analyze(self, tool: Dict[str, Any], source_code: str = None) -> List[Finding]:
        """Analysiert ein Tool auf gefährliche Operationen"""
        findings = []
        tool_name = tool.get("name", "unknown")
        
        # 1. Analyse der Tool-Metadaten
        findings.extend(self._analyze_tool_schema(tool))
        
        # 2. Quellcode-Analyse (falls verfügbar)
        if source_code:
            findings.extend(self._analyze_source_code(tool_name, source_code))
        
        return findings

    def _analyze_tool_schema(self, tool: Dict[str, Any]) -> List[Finding]:
        """Analysiert das JSON-Schema des Tools"""
        findings = []
        tool_name = tool.get("name", "unknown")
        input_schema = tool.get("inputSchema", {})
        properties = input_schema.get("properties", {})
        
        dangerous_params = ["command", "cmd", "shell", "path", "file", "url"]
        
        for param_name, param_schema in properties.items():
            if any(dp in param_name.lower() for dp in dangerous_params):
                if param_schema.get("type") == "string" and "enum" not in param_schema:
                    findings.append(Finding(
                        tool_name=tool_name,
                        risk_level=RiskLevel.MEDIUM,
                        category="dangerous_parameter",
                        description=f"Parameter '{param_name}' könnte gefährliche Eingaben akzeptieren",
                        location=f"inputSchema.properties.{param_name}",
                        remediation="Füge enum/pattern Constraints hinzu"
                    ))
        
        return findings

    def _analyze_source_code(self, tool_name: str, source_code: str) -> List[Finding]:
        """Analysiert den Quellcode"""
        findings = []
        
        for category, config in self.DANGEROUS_PATTERNS.items():
            for pattern in config["patterns"]:
                if re.search(pattern, source_code, re.IGNORECASE):
                    findings.append(Finding(
                        tool_name=tool_name,
                        risk_level=config["risk"],
                        category=category,
                        description=f"Gefährliche Operation erkannt: {pattern}",
                        location="source_code",
                        remediation=config["remediation"],
                        cwe_id=config.get("cwe")
                    ))
        
        return findings
