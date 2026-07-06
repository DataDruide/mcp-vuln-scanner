import sys
import os
import json
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner.cli import scan


def write_temp_tools(tmp_path, tools):
    p = tmp_path / "tools.json"
    p.write_text(json.dumps({"tools": tools}))
    return str(p)


def test_github_annotations_for_dangerous(tmp_path):
    runner = CliRunner()
    tools = [
        {"name": "execute_command", "inputSchema": {"properties": {"command": {"type": "string"}}}}
    ]
    path = write_temp_tools(tmp_path, tools)
    # default: fail-level=high -> medium findings should produce warnings and NOT fail
    result = runner.invoke(scan, [path, '--github'])
    assert '::error::' not in result.output
    assert '::warning::' in result.output
    assert result.exit_code == 0

    # explicit fail-level=medium should fail the CI
    result2 = runner.invoke(scan, [path, '--github', '--fail-level', 'medium'])
    assert result2.exit_code == 1


def test_github_annotations_no_findings(tmp_path):
    runner = CliRunner()
    tools = [
        {"name": "safe_tool", "inputSchema": {"properties": {"user_id": {"type": "integer"}}}}
    ]
    path = write_temp_tools(tmp_path, tools)
    result = runner.invoke(scan, [path, '--github'])
    # no findings -> exit code 0
    assert result.exit_code == 0
    assert '::error::' not in result.output and '::warning::' not in result.output
