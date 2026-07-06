"""
Threat Intelligence Database for MCP Security Scanner.

Maintains a database of known malicious, vulnerable, and suspicious MCP tools
and services for threat detection and reporting.
"""
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class ThreatSignature:
    """Represents a known threat signature."""
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low
    category: str  # malware, supply_chain, privilege_escalation, etc.
    indicators: List[str]  # Patterns to detect
    cve_ids: List[str]
    discovered_date: str
    last_updated: str
    mitigations: List[str]
    references: List[str]


@dataclass
class ThreatMatch:
    """Result of threat detection."""
    tool_name: str
    threat_id: str
    threat_name: str
    severity: str
    category: str
    indicator_matched: str
    confidence: float  # 0.0 to 1.0


class ThreatIntelligenceDB:
    """Threat Intelligence Database for MCP tools."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize threat intelligence database.
        
        Args:
            db_path: Path to threat database JSON file. 
                    If None, uses default location.
        """
        if db_path is None:
            # Default location relative to this file
            current_dir = Path(__file__).parent
            db_path = current_dir.parent.parent / "data" / "threat_intelligence.json"
        
        self.db_path = Path(db_path)
        self.threats: Dict[str, ThreatSignature] = {}
        self._load_database()

    def _load_database(self) -> None:
        """Load threat database from JSON file."""
        if not self.db_path.exists():
            self.threats = {}
            return

        try:
            with open(self.db_path, 'r') as f:
                data = json.load(f)
            
            for threat_dict in data.get("threats", []):
                threat = ThreatSignature(**threat_dict)
                self.threats[threat.id] = threat
        except Exception as e:
            print(f"Warning: Failed to load threat database: {e}")
            self.threats = {}

    def check_tool(self, tool_name: str, tool_definition: Optional[Dict[str, Any]] = None) -> List[ThreatMatch]:
        """Check tool against known threats.
        
        Args:
            tool_name: Name of the tool to check
            tool_definition: Optional tool schema/definition for deeper analysis
            
        Returns:
            List of threat matches found
        """
        matches: List[ThreatMatch] = []

        # Check tool name against indicators
        tool_name_lower = tool_name.lower()
        for threat_id, threat in self.threats.items():
            for indicator in threat.indicators:
                # Simple string matching (can be enhanced with regex)
                if indicator.lower() in tool_name_lower or tool_name_lower == indicator.lower():
                    match = ThreatMatch(
                        tool_name=tool_name,
                        threat_id=threat.id,
                        threat_name=threat.name,
                        severity=threat.severity,
                        category=threat.category,
                        indicator_matched=indicator,
                        confidence=0.9  # High confidence for exact matches
                    )
                    matches.append(match)

        # Check tool definition if provided
        if tool_definition:
            matches.extend(self._check_definition(tool_name, tool_definition))

        return matches

    def _check_definition(self, tool_name: str, definition: Dict[str, Any]) -> List[ThreatMatch]:
        """Check tool definition against threats.
        
        Args:
            tool_name: Tool name
            definition: Tool schema definition
            
        Returns:
            List of threat matches from definition analysis
        """
        matches: List[ThreatMatch] = []

        # Convert definition to string for pattern matching
        def_str = json.dumps(definition).lower()

        for threat_id, threat in self.threats.items():
            for indicator in threat.indicators:
                if indicator.lower() in def_str:
                    match = ThreatMatch(
                        tool_name=tool_name,
                        threat_id=threat.id,
                        threat_name=threat.name,
                        severity=threat.severity,
                        category=threat.category,
                        indicator_matched=indicator,
                        confidence=0.6  # Medium confidence for definition matches
                    )
                    matches.append(match)

        return matches

    def get_threat(self, threat_id: str) -> Optional[ThreatSignature]:
        """Get threat by ID.
        
        Args:
            threat_id: Threat signature ID
            
        Returns:
            ThreatSignature or None if not found
        """
        return self.threats.get(threat_id)

    def list_threats(self, severity: Optional[str] = None, category: Optional[str] = None) -> List[ThreatSignature]:
        """List threats, optionally filtered by severity or category.
        
        Args:
            severity: Optional severity level to filter by
            category: Optional category to filter by
            
        Returns:
            List of matching threats
        """
        threats = list(self.threats.values())

        if severity:
            threats = [t for t in threats if t.severity == severity]

        if category:
            threats = [t for t in threats if t.category == category]

        return threats

    def add_threat(self, threat: ThreatSignature) -> None:
        """Add threat to database.
        
        Args:
            threat: Threat signature to add
        """
        self.threats[threat.id] = threat

    def export_threats(self, output_path: Path) -> None:
        """Export threats to JSON file.
        
        Args:
            output_path: Path to write threats JSON
        """
        data = {
            "threats": [asdict(t) for t in self.threats.values()],
            "exported_at": datetime.now().isoformat(),
            "total_threats": len(self.threats)
        }
        output_path.write_text(json.dumps(data, indent=2))

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat database statistics.
        
        Returns:
            Dictionary with statistics
        """
        severity_counts = {}
        category_counts = {}

        for threat in self.threats.values():
            severity_counts[threat.severity] = severity_counts.get(threat.severity, 0) + 1
            category_counts[threat.category] = category_counts.get(threat.category, 0) + 1

        return {
            "total_threats": len(self.threats),
            "by_severity": severity_counts,
            "by_category": category_counts,
            "database_path": str(self.db_path)
        }
