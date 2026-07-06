import sys
import os
import json
from pathlib import Path
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner.sbom import generate_sbom_from_requirements, check_vulnerabilities_from_db
from src.scanner.cli import scan


def test_generate_sbom_from_requirements(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("insecurepkg==1.0.0\nsafe==0.1.0\n")
    sbom = generate_sbom_from_requirements(str(req))
    assert 'insecurepkg' in sbom
    assert 'pkg:pypi/insecurepkg@1.0.0' in sbom
    print("✅ SBOM generation works")


def test_vulnerability_check_and_cli(tmp_path):
    # write requirements
    req = tmp_path / "requirements.txt"
    req.write_text("insecurepkg==1.0.0\n")
    # write vuln db
    vuln_db = tmp_path / "vuln_db.json"
    vuln_db.write_text(json.dumps({"insecurepkg": ["1.0.0"]}))

    runner = CliRunner()
    # run cli with --sbom and --vuln-db; expect non-zero exit due to vulnerable dep
    result = runner.invoke(scan, [str(req), '--sbom', str(tmp_path / 'bom.json'), '--vuln-db', str(vuln_db)])
    assert result.exit_code != 0
    assert 'verwundbare Abhängigkeiten' in result.output or 'Vulnerable' in result.output
    print("✅ Vulnerability scan via CLI detected vulnerable dependency")
