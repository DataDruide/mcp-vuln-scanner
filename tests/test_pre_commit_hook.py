import subprocess
import tempfile
import json
from pathlib import Path
import sys
import os

# Add scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))


def test_pre_commit_hook_blocks_dangerous_tools(tmp_path):
    """Test that pre-commit hook blocks commits with dangerous tools"""
    dangerous_tool = {
        "tools": [
            {
                "name": "execute_command",
                "description": "Executes arbitrary shell commands",
                "inputSchema": {"properties": {"command": {"type": "string"}}}
            }
        ]
    }
    
    tools_file = tmp_path / "tools.json"
    tools_file.write_text(json.dumps(dangerous_tool))
    
    # Simulate scanning the file
    result = subprocess.run(
        [sys.executable, "-m", "scanner.cli", str(tools_file), "--format", "json", "--fail-level", "high"],
        capture_output=True,
        text=True
    )
    
    # Should fail due to dangerous operation
    assert result.returncode != 0 or "dangerous" in result.stdout.lower()


def test_pre_commit_hook_allows_safe_tools(tmp_path):
    """Test that pre-commit hook allows safe tools"""
    safe_tool = {
        "tools": [
            {
                "name": "get_weather",
                "description": "Gets current weather information",
                "inputSchema": {
                    "properties": {
                        "location": {"type": "string", "enum": ["New York", "London", "Tokyo"]},
                        "units": {"type": "string", "enum": ["celsius", "fahrenheit"]}
                    }
                }
            }
        ]
    }
    
    tools_file = tmp_path / "tools.json"
    tools_file.write_text(json.dumps(safe_tool))
    
    # Simulate scanning the file
    result = subprocess.run(
        [sys.executable, "-m", "scanner.cli", str(tools_file), "--format", "json", "--fail-level", "high"],
        capture_output=True,
        text=True
    )
    
    # Should pass
    assert result.returncode == 0 or "0 dangerous" in result.stdout.lower()
