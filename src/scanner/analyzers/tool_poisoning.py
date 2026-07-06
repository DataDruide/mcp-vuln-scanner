# src/scanner/analyzers/tool_poisoning.py
from dataclasses import dataclass
from typing import List, Dict, Any
from difflib import SequenceMatcher
import re


@dataclass
class PoisoningFinding:
    tool_name: str
    poisoning_type: str  # "typosquatting", "misleading_description", "suspicious_metadata"
    confidence: float  # 0.0 - 1.0
    description: str
    suggested_alternative: str = None


class ToolPoisoningDetector:
    """
    Erkennt Tool-Poisoning-Angriffe:
    - Typosquatting (ähnliche Namen bekannter Tools)
    - Irreführende Beschreibungen
    - Manipulierte Tool-Metadaten
    """
    
    # Bekannte vertrauenswürdige Tools
    TRUSTED_TOOLS = {
        "read_file", "write_file", "list_directory", "execute_command",
        "http_request", "database_query", "send_email", "search_web",
        "calculate", "get_weather", "send_sms", "make_call"
    }
    
    def analyze(self, tools: List[Dict[str, Any]]) -> List[PoisoningFinding]:
        """Analysiert alle Tools auf Poisoning-Indikatoren"""
        findings = []
        
        for tool in tools:
            tool_name = tool.get("name", "")
            description = tool.get("description", "")
            
            # 1. Typosquatting-Erkennung
            typosquatting = self._detect_typosquatting(tool_name)
            if typosquatting:
                findings.append(typosquatting)
            
            # 2. Irreführende Beschreibung
            misleading = self._detect_misleading_description(tool_name, description)
            if misleading:
                findings.append(misleading)
            
            # 3. Verdächtige Metadaten
            suspicious = self._detect_suspicious_metadata(tool)
            if suspicious:
                findings.extend(suspicious)
        
        return findings
    
    def _detect_typosquatting(self, tool_name: str) -> PoisoningFinding:
        """Erkennt Typosquatting durch Ähnlichkeitsanalyse"""
        tool_name_lower = tool_name.lower()
        
        for trusted in self.TRUSTED_TOOLS:
            # Ähnlichkeitsberechnung
            similarity = SequenceMatcher(None, tool_name_lower, trusted).ratio()
            
            # Wenn sehr ähnlich aber nicht identisch (80-95% Ähnlichkeit)
            if 0.8 < similarity < 0.95:
                return PoisoningFinding(
                    tool_name=tool_name,
                    poisoning_type="typosquatting",
                    confidence=similarity,
                    description=f"Tool-Name '{tool_name}' ist sehr ähnlich zu vertrauenswürdigem Tool '{trusted}'",
                    suggested_alternative=trusted
                )
        
        return None
    
    def _detect_misleading_description(self, tool_name: str, description: str) -> PoisoningFinding:
        """Erkennt irreführende Beschreibungen"""
        suspicious_patterns = [
            (r"(?i)securely|safe|trusted|verified", "Behauptet Sicherheitseigenschaften"),
            (r"(?i)official|authorized|standard|certified", "Behauptet offiziellen Status"),
            (r"(?i)admin|root|superuser|privileged", "Behauptet erhöhte Privilegien"),
            (r"(?i)best|fastest|most reliable|enterprise", "Übertriebene Marketing-Behauptungen"),
        ]
        
        description_lower = description.lower()
        
        for pattern, reason in suspicious_patterns:
            if re.search(pattern, description_lower):
                return PoisoningFinding(
                    tool_name=tool_name,
                    poisoning_type="misleading_description",
                    confidence=0.7,
                    description=f"Irreführende Beschreibung: {reason}"
                )
        
        return None
    
    def _detect_suspicious_metadata(self, tool: Dict[str, Any]) -> List[PoisoningFinding]:
        """Erkennt verdächtige Metadaten"""
        findings = []
        tool_name = tool.get("name", "unknown")
        
        # Prüfe auf extrem lange Beschreibungen (Prompt-Injection Risiko)
        description = tool.get("description", "")
        if len(description) > 2000:
            findings.append(PoisoningFinding(
                tool_name=tool_name,
                poisoning_type="suspicious_metadata",
                confidence=0.6,
                description=f"Ungewöhnlich lange Beschreibung ({len(description)} Zeichen) – mögliche Prompt-Injection"
            ))
        
        # Prüfe auf verdächtige Parameter-Namen
        input_schema = tool.get("inputSchema", {})
        properties = input_schema.get("properties", {})
        
        suspicious_params = ["prompt", "instruction", "sql", "query_raw", "command_raw", "eval"]
        
        for param_name, param_schema in properties.items():
            param_lower = param_name.lower()
            if any(sp in param_lower for sp in suspicious_params):
                if param_schema.get("type") == "string" and "enum" not in param_schema:
                    findings.append(PoisoningFinding(
                        tool_name=tool_name,
                        poisoning_type="suspicious_parameter",
                        confidence=0.5,
                        description=f"Verdächtiger Parameter '{param_name}' ohne Einschränkungen – könnte für Prompt-Injection genutzt werden"
                    ))
        
        return findings
