import json
from pathlib import Path
from typing import Dict, List


def parse_requirements(req_path: str) -> List[Dict[str, str]]:
    """Parst eine einfache requirements.txt mit Zeilen `name==version`."""
    comps = []
    p = Path(req_path)
    if not p.exists():
        return comps
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '==' in line:
            name, ver = line.split('==', 1)
            comps.append({'name': name.strip(), 'version': ver.strip()})
        else:
            comps.append({'name': line, 'version': ''})
    return comps


def generate_sbom_from_requirements(req_path: str) -> str:
    """Generiert ein einfaches CycloneDX-ähnliches SBOM JSON aus einer requirements.txt."""
    components = parse_requirements(req_path)
    bom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'components': []
    }
    for c in components:
        comp = {
            'name': c['name'],
            'version': c['version'],
            'purl': f"pkg:pypi/{c['name']}@{c['version']}" if c['version'] else f"pkg:pypi/{c['name']}"
        }
        bom['components'].append(comp)
    return json.dumps(bom, indent=2)


def check_vulnerabilities_from_db(sbom_json: str, vuln_db_path: str) -> List[Dict]:
    """Prüft Komponenten im SBOM gegen eine einfache Vulnerability-DB.

    Vulnerability DB format: {"package_name": ["1.0.0", "2.3.4"]}
    Matches exact versions.
    """
    findings = []
    try:
        db = json.loads(Path(vuln_db_path).read_text())
    except Exception:
        return findings

    bom = json.loads(sbom_json)
    for comp in bom.get('components', []):
        name = comp.get('name')
        ver = comp.get('version')
        vuln_versions = db.get(name, [])
        if ver and ver in vuln_versions:
            findings.append({
                'package': name,
                'version': ver,
                'description': f"Vulnerable version {ver} detected for {name}"
            })
    return findings
