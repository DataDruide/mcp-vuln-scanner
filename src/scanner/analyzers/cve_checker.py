# src/scanner/analyzers/cve_checker.py
import requests
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass
import time

@dataclass
class CVEFinding:
    package_name: str
    package_version: str
    cve_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    cvss_score: float
    cvss_vector: str
    published_date: str
    last_modified: str
    remediation: str
    references: List[str]

class CVEChecker:
    """Prüft Pakete auf bekannte CVEs über NVD API"""
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, cache_dir: Path = None, api_key: str = None):
        self.cache_dir = cache_dir or Path.home() / ".mcp-scanner" / "cve_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key
        self.cache_db = self.cache_dir / "cve_cache.db"
        self._init_cache()
    
    def _init_cache(self):
        """Initialisiert SQLite-Cache für CVE-Daten"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                package_name TEXT,
                package_version TEXT,
                cve_data TEXT,
                last_updated TIMESTAMP,
                PRIMARY KEY (package_name, package_version)
            )
        """)
        conn.commit()
        conn.close()
    
    def check_package(self, package_name: str, version: str) -> List[CVEFinding]:
        """Prüft ein einzelnes Package auf CVEs"""
        
        # Cache prüfen
        cached = self._get_cached(package_name, version)
        if cached:
            return cached
        
        # NVD API abfragen
        findings = self._query_nvd(package_name, version)
        
        # Cache speichern
        self._cache_findings(package_name, version, findings)
        
        return findings
    
    def check_packages(self, packages: Dict[str, str]) -> List[CVEFinding]:
        """Prüft mehrere Packages auf CVEs"""
        all_findings = []
        for pkg, ver in packages.items():
            findings = self.check_package(pkg, ver)
            all_findings.extend(findings)
            time.sleep(0.5)  # Rate-Limiting für NVD API
        return all_findings
    
    def _query_nvd(self, package_name: str, version: str) -> List[CVEFinding]:
        """Fragt NVD API ab"""
        findings = []
        
        # Build API query
        query = f'cpe:2.3:a:*:{package_name}:{version}:*:*:*:*:*:*:*'
        params = {
            "cpeName": query,
            "resultsPerPage": 50
        }
        
        if self.api_key:
            params["apiKey"] = self.api_key
        
        try:
            response = requests.get(
                self.NVD_API_URL,
                params=params,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    metrics = cve.get("metrics", {})
                    
                    # Severity aus CVSS v3 oder v2
                    cvss_data = None
                    severity = "LOW"
                    cvss_score = 0.0
                    cvss_vector = ""
                    
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                        severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                        cvss_score = cvss_data["baseScore"]
                        cvss_vector = cvss_data["vectorString"]
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                        severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                        cvss_score = cvss_data["baseScore"]
                        cvss_vector = cvss_data["vectorString"]
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                        severity = metrics["cvssMetricV2"][0]["severity"]
                        cvss_score = cvss_data["baseScore"]
                        cvss_vector = cvss_data["vectorString"]
                    
                    findings.append(CVEFinding(
                        package_name=package_name,
                        package_version=version,
                        cve_id=cve.get("id", "Unknown"),
                        severity=severity.upper(),
                        description=cve.get("descriptions", [{}])[0].get("value", "No description")[:500],
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        published_date=cve.get("published", ""),
                        last_modified=cve.get("lastModified", ""),
                        remediation=f"Update {package_name} auf eine neuere Version",
                        references=[ref.get("url", "") for ref in cve.get("references", [])[:5]]
                    ))
            
        except Exception as e:
            print(f"Fehler bei NVD-Abfrage für {package_name}: {e}")
        
        return findings
    
    def _get_cached(self, package_name: str, version: str) -> Optional[List[CVEFinding]]:
        """Holt gecachte Ergebnisse"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT cve_data, last_updated FROM cve_cache WHERE package_name = ? AND package_version = ?",
            (package_name, version)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            # Cache älter als 7 Tage?
            last_updated = datetime.fromisoformat(row[1])
            if datetime.now() - last_updated < timedelta(days=7):
                return json.loads(row[0])
        
        return None
    
    def _cache_findings(self, package_name: str, version: str, findings: List[CVEFinding]):
        """Cachet Ergebnisse"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        # In JSON umwandeln
        findings_json = []
        for f in findings:
            findings_json.append({
                "cve_id": f.cve_id,
                "severity": f.severity,
                "description": f.description,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "published_date": f.published_date,
                "last_modified": f.last_modified,
                "remediation": f.remediation,
                "references": f.references
            })
        
        cursor.execute(
            "INSERT OR REPLACE INTO cve_cache (package_name, package_version, cve_data, last_updated) VALUES (?, ?, ?, ?)",
            (package_name, version, json.dumps(findings_json), datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
