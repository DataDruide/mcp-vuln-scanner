import re
import os
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class SecretFinding:
    tool_name: str
    secret_type: str
    location: str
    description: str
    severity: str

class SecretDetector:
    """Erkennt API-Keys, Passwörter und Tokens in MCP-Tools"""
    
    PATTERNS = {
        "OpenAI API Key": {
            "pattern": r'sk-[a-zA-Z0-9]{48}',
            "severity": "critical",
            "description": "OpenAI API Key gefunden – kann zu unautorisierten Kosten führen"
        },
        "GitHub Token": {
            "pattern": r'ghp_[a-zA-Z0-9]{36}',
            "severity": "critical",
            "description": "GitHub Personal Access Token gefunden"
        },
        "AWS Key": {
            "pattern": r'AKIA[0-9A-Z]{16}',
            "severity": "critical",
            "description": "AWS Access Key ID gefunden"
        },
        "AWS Secret": {
            "pattern": r'[a-zA-Z0-9/+=]{40}',
            "severity": "critical",
            "description": "AWS Secret Access Key gefunden (muss mit AWS Key kombiniert werden)"
        },
        "Slack Webhook": {
            "pattern": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+',
            "severity": "high",
            "description": "Slack Webhook URL gefunden"
        },
        "Jira Token": {
            "pattern": r'[a-zA-Z0-9]{24}',
            "severity": "high",
            "description": "Jira API Token gefunden (muss im Kontext geprüft werden)"
        },
        "Generic API Key": {
            "pattern": r'[a-zA-Z0-9]{32,}',
            "severity": "medium",
            "description": "Möglicher API Key (32+ Zeichen alphanumerisch)"
        },
        "Password": {
            "pattern": r'password["\']?\s*[:=]\s*["\'][^"\']+["\']',
            "severity": "critical",
            "description": "Klartext-Passwort gefunden"
        },
        "Private Key": {
            "pattern": r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            "severity": "critical",
            "description": "Privater SSH/RSA-Schlüssel gefunden"
        }
    }
    
    def analyze(self, tool: Dict[str, Any]) -> List[SecretFinding]:
        """Analysiert ein Tool auf Secrets"""
        findings = []
        tool_name = tool.get("name", "unknown")
        tool_str = json.dumps(tool)
        
        for secret_type, config in self.PATTERNS.items():
            matches = re.findall(config["pattern"], tool_str, re.IGNORECASE)
            for match in matches[:3]:  # Max 3 pro Typ
                findings.append(SecretFinding(
                    tool_name=tool_name,
                    secret_type=secret_type,
                    location=f"in {tool_name}",
                    description=f"{config['description']}: {match[:20]}...",
                    severity=config["severity"]
                ))
        
        return findings

import json
