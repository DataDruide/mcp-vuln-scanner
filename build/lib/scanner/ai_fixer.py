import os
import requests
import json

class AIFixer:
    def __init__(self, provider="openai", api_key=None, model=None):
        self.provider = os.environ.get("AI_PROVIDER", provider).lower()
        self.api_key = api_key or os.environ.get("AI_API_KEY")
        self.model = model or os.environ.get("AI_MODEL")

        # Standard-Modelle je nach Provider
        if self.provider == "openai" and not self.model:
            self.model = "gpt-3.5-turbo"
        elif self.provider == "ollama" and not self.model:
            self.model = "llama3.2"
        elif self.provider == "gemini" and not self.model:
            self.model = "gemini-1.5-flash"

    def generate_fix(self, finding):
        """Generiert Fix-Vorschlag basierend auf dem gewählten Provider"""
        prompt = f"""Fix this MCP tool security issue:
Tool: {finding.tool_name}
Problem: {finding.description}
Risk: {finding.risk_level.value}
Location: {finding.location}

Provide a specific fix with code example in JSON schema format."""
        
        if self.provider == "openai":
            return self._call_openai(prompt)
        elif self.provider == "ollama":
            return self._call_ollama(prompt)
        elif self.provider == "gemini":
            return self._call_gemini(prompt)
        else:
            return finding.remediation
    
    def _call_openai(self, prompt):
        """OpenAI API"""
        try:
            import openai
            openai.api_key = self.api_key
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[OpenAI Error: {e}]"
    
    def _call_ollama(self, prompt):
        """Ollama (lokal, kostenlos)"""
        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3}
                },
                timeout=60
            )
            if response.status_code == 200:
                return response.json().get("response", "No response")
            return f"[Ollama Error] Server not running"
        except Exception as e:
            return f"[Ollama Error] {e}"
    
    def _call_gemini(self, prompt):
        """Google Gemini API"""
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(self.model)
            response = model.generate_content(prompt)
            return response.text
        except ImportError:
            return "[Gemini Error] Install: pip install google-generativeai"
        except Exception as e:
            return f"[Gemini Error] {e}"

    def apply_fix(self, tool, finding, fix_suggestion):
        """Wendet den AI-Fix auf das Tool an"""
        import re
        import json
        
        # Extrahiere JSON aus der Antwort
        json_match = re.search(r'```json\n(.*?)\n```', fix_suggestion, re.DOTALL)
        if json_match:
            try:
                fix_json = json.loads(json_match.group(1))
                if 'properties' in fix_json:
                    if 'inputSchema' not in tool:
                        tool['inputSchema'] = {}
                    if 'properties' not in tool['inputSchema']:
                        tool['inputSchema']['properties'] = {}
                    
                    for prop_name, prop_schema in fix_json['properties'].items():
                        if prop_name in tool['inputSchema']['properties']:
                            tool['inputSchema']['properties'][prop_name].update(prop_schema)
                        else:
                            tool['inputSchema']['properties'][prop_name] = prop_schema
                    
                    return True, tool
            except:
                pass
        
        # Fallback
        if finding.category == "dangerous_parameter":
            param_name = finding.location.split('.')[-1]
            if param_name in tool.get('inputSchema', {}).get('properties', {}):
                tool['inputSchema']['properties'][param_name]['pattern'] = '^[a-zA-Z0-9_/.-]+$'
                tool['inputSchema']['properties'][param_name]['maxLength'] = 255
                return True, tool
        
        return False, tool

    def generate_patch(self, original_tool, updated_tool):
        """Generate a unified diff (git-style) between original and updated tool JSON."""
        import json
        import difflib

        a = json.dumps(original_tool, indent=2, sort_keys=True).splitlines(keepends=True)
        b = json.dumps(updated_tool, indent=2, sort_keys=True).splitlines(keepends=True)
        diff = difflib.unified_diff(a, b, fromfile='a/tool.json', tofile='b/tool.json')
        return ''.join(diff)


if __name__ == "__main__":
    from scanner.analyzers.dangerous_ops import Finding, RiskLevel
    test_finding = Finding(
        tool_name="execute_command",
        risk_level=RiskLevel.HIGH,
        category="command_injection",
        description="Command injection risk",
        location="inputSchema.properties.command",
        remediation="Use whitelist"
    )
    fixer = AIFixer(provider="ollama")
    print(fixer.generate_fix(test_finding))
