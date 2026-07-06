import pytest
from pathlib import Path
from src.scanner.threat_db import ThreatIntelligenceDB, ThreatSignature


def test_threat_db_loads_successfully():
    """Test that threat database loads successfully."""
    db = ThreatIntelligenceDB()
    assert len(db.threats) > 0
    assert db.get_statistics()["total_threats"] > 0


def test_threat_db_detects_known_threats():
    """Test that known threats are detected."""
    db = ThreatIntelligenceDB()
    
    # Test detection by tool name
    matches = db.check_tool("execute_code")
    assert len(matches) > 0
    assert any(m.severity == "critical" for m in matches)


def test_threat_db_filters_by_severity():
    """Test filtering threats by severity."""
    db = ThreatIntelligenceDB()
    
    critical_threats = db.list_threats(severity="critical")
    assert len(critical_threats) > 0
    assert all(t.severity == "critical" for t in critical_threats)


def test_threat_db_filters_by_category():
    """Test filtering threats by category."""
    db = ThreatIntelligenceDB()
    
    code_exec_threats = db.list_threats(category="code_execution")
    assert len(code_exec_threats) > 0
    assert all(t.category == "code_execution" for t in code_exec_threats)


def test_threat_db_get_threat():
    """Test retrieving specific threat by ID."""
    db = ThreatIntelligenceDB()
    
    threat = db.get_threat("TI-2024-001")
    assert threat is not None
    assert threat.name == "Arbitrary Code Execution Tool"
    assert threat.severity == "critical"


def test_threat_db_multiple_indicator_matching():
    """Test threat matching with multiple indicators."""
    db = ThreatIntelligenceDB()
    
    # Should detect multiple patterns in threat indicators
    for tool_name in ["execute_code", "eval_code", "run_command"]:
        matches = db.check_tool(tool_name)
        assert len(matches) > 0


def test_threat_signature_creation():
    """Test creating threat signatures."""
    threat = ThreatSignature(
        id="TEST-001",
        name="Test Threat",
        description="A test threat",
        severity="high",
        category="test",
        indicators=["test_indicator"],
        cve_ids=[],
        discovered_date="2024-07-06",
        last_updated="2024-07-06",
        mitigations=["Test mitigation"],
        references=[]
    )
    
    assert threat.id == "TEST-001"
    assert threat.severity == "high"
    assert "test_indicator" in threat.indicators
