class MCPGuard:
    def __init__(self, policy):
        self.policy = policy

    def before_tool_call(self, tool_name, args):
        self._check_injection(args)
        self._check_permissions(tool_name)

    def after_tool_call(self, tool_name, result):
        self._check_data_leak(result)

    def _check_injection(self, args):
        data = str(args)

        dangerous_patterns = [
            "rm -rf",
            "exec(",
            "subprocess",
            "os.system",
            "DROP TABLE"
        ]

        for pattern in dangerous_patterns:
            if pattern in data:
                raise Exception(f"🚨 Injection detected: {pattern}")

    def _check_permissions(self, tool_name):
        if tool_name in self.policy.get("blocked_tools", []):
            raise Exception(f"🚫 Tool blocked: {tool_name}")

    def _check_data_leak(self, result):
        if "PRIVATE_KEY" in str(result):
            raise Exception("🔑 Secret leak detected!")
