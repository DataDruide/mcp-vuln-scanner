import json
import os
from pathlib import Path

import pytest

from scanner.cli import discover_tools_from_target, load_scan_config, apply_exclusions


def test_discover_tools_from_directory(tmp_path):
    subdir = tmp_path / "nested"
    subdir.mkdir()
    (tmp_path / "tools_a.json").write_text(json.dumps({"tools": [{"name": "alpha"}]}), encoding="utf-8")
    (subdir / "tools_b.json").write_text(json.dumps({"tools": [{"name": "beta"}]}), encoding="utf-8")

    tools = discover_tools_from_target(str(tmp_path))

    assert [tool["name"] for tool in tools] == ["alpha", "beta"]


def test_load_scan_config_supports_json(tmp_path):
    config_file = tmp_path / "scan.json"
    config_file.write_text(json.dumps({"format": "json", "secrets": True, "fail_level": "critical"}), encoding="utf-8")

    cfg = load_scan_config(config_file)

    assert cfg["format"] == "json"
    assert cfg["secrets"] is True
    assert cfg["fail_level"] == "critical"


def test_apply_exclusions_filters_tool_names():
    tools = [{"name": "alpha"}, {"name": "beta"}, {"name": "gamma"}]

    filtered = apply_exclusions(tools, ["alpha", "beta"])

    assert [tool["name"] for tool in filtered] == ["gamma"]
