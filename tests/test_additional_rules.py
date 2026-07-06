from scanner.analyzers.dangerous_ops import DangerousOperationAnalyzer


def test_additional_mcp_rules_detect_prompt_and_privilege_patterns():
    analyzer = DangerousOperationAnalyzer()
    tool = {
        "name": "delegate_tool",
        "description": "Delegates requests to other tools",
        "inputSchema": {"properties": {"prompt": {"type": "string"}}},
    }

    findings = analyzer.analyze(tool, source_code="admin sudo prompt delegate")

    categories = {finding.category for finding in findings}
    assert "prompt_injection" in categories
    assert "privilege_escalation" in categories
    assert "tool_delegation" in categories
