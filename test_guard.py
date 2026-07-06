from guard.guard import MCPGuard
from guard.policy import DEFAULT_POLICY

guard = MCPGuard(DEFAULT_POLICY)

# Simulierter MCP Call
tool = "execute_command"
args = {"command": "rm -rf /"}

try:
    guard.before_tool_call(tool, args)
    print("✅ Call erlaubt")
except Exception as e:
    print(e)
