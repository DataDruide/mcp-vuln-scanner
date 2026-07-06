# src/scanner/discovery/mcp_client.py
import json
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import sseclient
import requests

@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: Dict[str, Any]
    
class MCPClient:
    """MCP-Protokoll-Client für Live-Scanning"""
    
    def __init__(self, server_url: str, timeout: int = 30):
        self.server_url = server_url.rstrip('/')
        self.timeout = timeout
    
    def list_tools(self) -> List[MCPTool]:
        """Listet alle Tools des MCP-Servers"""
        
        # Versuche SSE-Endpoint
        sse_url = f"{self.server_url}/sse"
        tools = self._list_tools_sse(sse_url)
        if tools:
            return tools
        
        # Versuche HTTP-Endpoint
        return self._list_tools_http()
    
    def _list_tools_http(self) -> List[MCPTool]:
        """Listet Tools über HTTP-API"""
        try:
            # MCP Standard-Endpoint
            response = requests.post(
                f"{self.server_url}/tools/list",
                json={},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                tools = []
                for tool in data.get("tools", []):
                    tools.append(MCPTool(
                        name=tool.get("name", "unknown"),
                        description=tool.get("description", ""),
                        input_schema=tool.get("inputSchema", {})
                    ))
                return tools
            
        except Exception as e:
            print(f"HTTP-Fehler: {e}")
        
        return []
    
    def _list_tools_sse(self, sse_url: str) -> List[MCPTool]:
        """Listet Tools über Server-Sent Events"""
        tools = []
        
        try:
            response = requests.get(sse_url, stream=True, timeout=self.timeout)
            client = sseclient.SSEClient(response)
            
            for event in client.events():
                if event.event == "tool_list":
                    data = json.loads(event.data)
                    for tool in data.get("tools", []):
                        tools.append(MCPTool(
                            name=tool.get("name", "unknown"),
                            description=tool.get("description", ""),
                            input_schema=tool.get("inputSchema", {})
                        ))
                    break
                elif event.event == "error":
                    break
                    
        except Exception as e:
            print(f"SSE-Fehler: {e}")
        
        return tools
    
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict]:
        """Ruft ein Tool auf dem MCP-Server auf"""
        try:
            response = requests.post(
                f"{self.server_url}/tools/call",
                json={
                    "name": tool_name,
                    "arguments": arguments
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
                
        except Exception as e:
            print(f"Fehler beim Aufruf von {tool_name}: {e}")
        
        return None


class AsyncMCPClient:
    """Asynchroner MCP-Protokoll-Client"""
    
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')
    
    async def list_tools_async(self) -> List[MCPTool]:
        """Asynchrones Auflisten von Tools"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.server_url}/tools/list",
                    json={},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    data = await response.json()
                    tools = []
                    for tool in data.get("tools", []):
                        tools.append(MCPTool(
                            name=tool.get("name", "unknown"),
                            description=tool.get("description", ""),
                            input_schema=tool.get("inputSchema", {})
                        ))
                    return tools
            except Exception as e:
                print(f"Async-Fehler: {e}")
                return []
    
    async def scan_server(self) -> Dict[str, Any]:
        """Kompletter Scan eines MCP-Servers"""
        tools = await self.list_tools_async()
        
        return {
            "url": self.server_url,
            "tool_count": len(tools),
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema
                }
                for t in tools
            ]
        }
