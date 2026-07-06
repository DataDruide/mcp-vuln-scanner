import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner.plugin import PluginManager


def test_plugin_manager_discovers_no_errors():
    pm = PluginManager()
    analyzers, reporters = pm.discover()
    # Should return lists (possibly empty) and not raise
    assert isinstance(analyzers, list)
    assert isinstance(reporters, list)
    print("✅ PluginManager runs without errors")
