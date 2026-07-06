import hashlib
import json
import requests
from datetime import datetime, timedelta
from typing import Optional
import os

class LicenseValidator:
    """Prüft und validiert Pro-Lizenzen"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        # Live-Server auf Render (Produktion)
        self.api_url = os.environ.get("MCP_SCANNER_API_URL", "https://mcp-license-server.onrender.com/v1/license")
        self.cache_file = os.path.expanduser("~/.mcp-scanner/license.cache")
        
    def validate(self, license_key: str) -> dict:
        """Prüft einen Lizenzschlüssel"""
        if not license_key:
            return {"valid": False, "plan": "free", "features": [], "error": None}
        
        # 1. Cache prüfen (Offline-Modus)
        cached = self._check_cache(license_key)
        if cached and cached.get("valid_until", datetime.min) > datetime.now():
            return cached
        
        # 2. Online-Prüfung gegen Render-Server
        try:
            response = requests.post(
                self.api_url,
                json={
                    "license_key": license_key,
                    "machine_id": self._get_machine_id(),
                    "version": "1.0.0"
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                self._save_cache(license_key, result)
                return result
            else:
                # Fallback: Cache verwenden
                if cached:
                    return cached
                return {"valid": False, "plan": "free", "features": [], "error": f"API error: {response.status_code}"}
                
        except Exception as e:
            # Offline-Fallback: Cache verwenden
            if cached:
                return cached
            
            return {
                "valid": False,
                "error": f"Lizenzprüfung fehlgeschlagen: {e}",
                "plan": "free",
                "features": []
            }
    
    def _get_machine_id(self) -> str:
        """Generiert eine eindeutige Maschinen-ID"""
        import platform
        machine = f"{platform.node()}-{platform.processor()}-{platform.machine()}"
        return hashlib.sha256(machine.encode()).hexdigest()[:16]
    
    def _check_cache(self, license_key: str) -> Optional[dict]:
        """Prüft lokalen Cache"""
        if not os.path.exists(self.cache_file):
            return None
        
        try:
            with open(self.cache_file, 'r') as f:
                cache = json.load(f)
                if cache.get("license_key") == license_key:
                    cache["valid_until"] = datetime.fromisoformat(cache["valid_until"])
                    return cache
        except:
            pass
        
        return None
    
    def _save_cache(self, license_key: str, data: dict):
        """Speichert Lizenz im Cache"""
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        
        cache_data = {
            "license_key": license_key,
            "valid": data.get("valid", False),
            "plan": data.get("plan", "free"),
            "features": data.get("features", []),
            "valid_until": data.get("valid_until", (datetime.now() + timedelta(days=7)).isoformat())
        }
        
        with open(self.cache_file, 'w') as f:
            json.dump(cache_data, f)
