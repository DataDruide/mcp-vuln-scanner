import requests
import os
from typing import List, Dict, Any

def send_discord_alert(findings: Dict[str, Any], webhook_url: str = None):
    """Sendet Findings als Discord Nachricht"""
    
    webhook_url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        print("❌ Discord Webhook nicht konfiguriert")
        return False
    
    dangerous = findings.get("dangerous", [])
    poisoning = findings.get("poisoning", [])
    secrets = findings.get("secrets", [])
    
    # Farben
    if len(dangerous) > 0:
        color = 0xff3366  # Rot
    elif len(secrets) > 0:
        color = 0xff9933  # Orange
    else:
        color = 0x00ff9d  # Grün
    
    embed = {
        "title": "🔒 MCP Security Scanner",
        "color": color,
        "timestamp": "Z",
        "fields": [
            {"name": "⚠️ Dangerous Operations", "value": str(len(dangerous)), "inline": True},
            {"name": "🎭 Tool Poisoning", "value": str(len(poisoning)), "inline": True},
            {"name": "🔑 Secrets Found", "value": str(len(secrets)), "inline": True}
        ],
        "footer": {"text": "MCP Vulnerability Scanner"}
    }
    
    # Details für kritische Findings
    critical_findings = []
    for f in dangerous[:5]:
        critical_findings.append(f"**{f.tool_name}** [{f.risk_level.value}]: {f.description[:100]}")
    for f in secrets[:3]:
        critical_findings.append(f"**{f.tool_name}** 🔑 {f.secret_type}: {f.description[:100]}")
    
    if critical_findings:
        embed["fields"].append({
            "name": "📋 Kritische Findings",
            "value": "\n".join(critical_findings),
            "inline": False
        })
    
    try:
        response = requests.post(webhook_url, json={"embeds": [embed]}, timeout=10)
        return response.status_code == 204 or response.status_code == 200
    except Exception as e:
        print(f"❌ Discord Fehler: {e}")
        return False
