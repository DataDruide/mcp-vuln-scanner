import json
from pathlib import Path

from scanner.cli import load_scan_config


def test_load_scan_config_from_yaml(tmp_path):
    config_file = tmp_path / "scan.yaml"
    config_file.write_text("format: json\nsecrets: true\nfail_level: critical\n", encoding="utf-8")

    config = load_scan_config(config_file)

    assert config["format"] == "json"
    assert config["secrets"] is True
    assert config["fail_level"] == "critical"


def test_sbom_generation_creates_output_file(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\n", encoding="utf-8")
    output = tmp_path / "sbom.json"

    from scanner.sbom import generate_sbom_from_requirements

    content = generate_sbom_from_requirements(str(requirements))
    output.write_text(content, encoding="utf-8")

    assert output.exists()
    assert "requests" in content.lower()
