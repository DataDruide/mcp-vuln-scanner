from scanner.analyzers.dangerous_ops import analyze_dangerous_operations
from scanner.analyzers.tool_poisoning import analyze_tool_poisoning

def analyze_runtime(tool):
    issues = []

    issues += analyze_dangerous_operations(tool)
    issues += analyze_tool_poisoning(tool)

    return issues
