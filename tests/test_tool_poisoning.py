# tests/test_tool_poisoning.py
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner.analyzers.tool_poisoning import ToolPoisoningDetector, PoisoningFinding

def test_typosquatting_detection():
    detector = ToolPoisoningDetector()
    
    tools = [
        {"name": "read_fyle", "description": "Reads a file"},  # Typosquatting
        {"name": "read_file", "description": "Reads a file"},   # Legit
    ]
    
    findings = detector.analyze(tools)
    
    # Sollte Typosquatting finden
    typosquatting = [f for f in findings if f.poisoning_type == "typosquatting"]
    assert len(typosquatting) >= 1
    assert "read_fyle" in typosquatting[0].tool_name
    print("✅ Test 1: Typosquatting erkannt")

def test_misleading_description():
    detector = ToolPoisoningDetector()
    
    tools = [
        {"name": "suspicious_tool", "description": "OFFICIAL SECURE verified admin tool"}
    ]
    
    findings = detector.analyze(tools)
    
    misleading = [f for f in findings if f.poisoning_type == "misleading_description"]
    assert len(misleading) >= 1
    print("✅ Test 2: Irreführende Beschreibung erkannt")

def test_suspicious_parameter():
    detector = ToolPoisoningDetector()
    
    tools = [
        {
            "name": "dangerous_tool",
            "description": "Executes commands",
            "inputSchema": {
                "properties": {
                    "prompt": {"type": "string"},  # Verdächtiger Parameter
                    "command_raw": {"type": "string"}  # Verdächtiger Parameter
                }
            }
        }
    ]
    
    findings = detector.analyze(tools)
    
    suspicious = [f for f in findings if f.poisoning_type == "suspicious_parameter"]
    assert len(suspicious) >= 2  # Sollte beide Parameter finden
    print("✅ Test 3: Verdächtige Parameter erkannt")

def test_safe_tool():
    detector = ToolPoisoningDetector()
    
    tools = [
        {
            "name": "calculate",
            "description": "Performs mathematical calculations",
            "inputSchema": {
                "properties": {
                    "expression": {"type": "string", "enum": ["add", "subtract", "multiply"]}
                }
            }
        }
    ]
    
    findings = detector.analyze(tools)
    
    assert len(findings) == 0
    print("✅ Test 4: Sicheres Tool ohne Findings")

if __name__ == "__main__":
    test_typosquatting_detection()
    test_misleading_description()
    test_suspicious_parameter()
    test_safe_tool()
    print("\n🎉 Alle Tool-Poisoning Tests bestanden!")
