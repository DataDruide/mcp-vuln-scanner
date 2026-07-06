Packaging & Release notes

- Build a source distribution:

  python -m build

- Publish to PyPI (recommended flow):

  python -m pip install --upgrade build twine
  python -m build
  python -m twine upload dist/*

- Build Docker image:

  docker build -t mcp-vuln-scanner:latest .
