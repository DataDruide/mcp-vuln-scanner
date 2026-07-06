from typing import List, Type
import importlib
import pkgutil


class AnalyzerPlugin:
    """Base class for analyzer plugins."""
    name = "base-analyzer"

    def analyze(self, tool, source_code=None):
        raise NotImplementedError()


class ReporterPlugin:
    """Base class for reporter plugins."""
    name = "base-reporter"

    def generate(self, findings, score=None):
        raise NotImplementedError()


class PluginManager:
    """Discover plugins in the `scanner.plugins` package and return analyzer/reporter classes."""

    def __init__(self, package="scanner.plugins"):
        self.package = package

    def _iter_modules(self):
        try:
            package = importlib.import_module(self.package)
        except Exception:
            return
        for _, modname, ispkg in pkgutil.iter_modules(package.__path__):
            yield f"{self.package}.{modname}"

    def discover(self):
        analyzers: List[Type[AnalyzerPlugin]] = []
        reporters: List[Type[ReporterPlugin]] = []

        # Import builtins by default (existing analyzer/reporter modules)
        # External plugins can be added under scanner.plugins package
        for modname in self._iter_modules() or []:
            try:
                mod = importlib.import_module(modname)
            except Exception:
                continue
            for attr in dir(mod):
                obj = getattr(mod, attr)
                try:
                    if isinstance(obj, type) and issubclass(obj, AnalyzerPlugin) and obj is not AnalyzerPlugin:
                        analyzers.append(obj())
                    if isinstance(obj, type) and issubclass(obj, ReporterPlugin) and obj is not ReporterPlugin:
                        reporters.append(obj())
                except Exception:
                    continue

        return analyzers, reporters
