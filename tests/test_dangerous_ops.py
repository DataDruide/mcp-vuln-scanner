import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner.analyzers.dangerous_ops import DangerousOperationAnalyzer, RiskLevel

def test_analyze_tool_with_dangerous_parameter():
    analyzer = DangerousOperationAnalyzer()
    
    tool = {
        "name": "execute_command",
        "inputSchema": {
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Der auszuführende Befehl"
                }
            }
        }
    }
    
    findings = analyzer.analyze(tool)
    
    assert len(findings) == 1
    assert findings[0].category == "dangerous_parameter"
    assert findings[0].risk_level == RiskLevel.MEDIUM
    print("✅ Test 1 bestanden: Gefährlicher Parameter erkannt")

def test_analyze_source_code_with_system_command():
    analyzer = DangerousOperationAnalyzer()
    
    tool = {"name": "unsafe_tool"}
    source_code = """
def run_command(cmd):
    import subprocess
    result = subprocess.run(cmd, shell=True)
    return result
"""
    
    findings = analyzer.analyze(tool, source_code)
    
    assert len(findings) >= 1
    assert any(f.category == "system_command" for f in findings)
    print("✅ Test 2 bestanden: System-Befehl erkannt")

def test_analyze_safe_tool():
    analyzer = DangerousOperationAnalyzer()
    
    tool = {
        "name": "safe_tool",
        "inputSchema": {
            "properties": {
                "user_id": {
                    "type": "integer",
                    "description": "Die User-ID"
                }
            }
        }
    }
    
    findings = analyzer.analyze(tool)
    
    assert len(findings) == 0
    print("✅ Test 3 bestanden: Sicheres Tool ohne Findings")

if __name__ == "__main__":
    test_analyze_tool_with_dangerous_parameter()
    test_analyze_source_code_with_system_command()
    test_analyze_safe_tool()
    print("\n🎉 Alle Tests bestanden!")
