from setuptools import setup, find_packages

setup(
    name="mcp-vuln-scanner",
    version="1.2.0",
    description="AI-powered security vulnerability scanner for MCP (Model Context Protocol) servers with automatic fixes, secret detection, and multi-channel alerts",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="DataDruide",
    author_email="your-email@example.com",
    url="https://github.com/DataDruide/mcp-vuln-scanner",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "click>=8.0.0",
        "pyyaml>=6.0",
        "jsonschema>=4.0",
        "requests>=2.28",
        "tomli>=2.0.0",
        "aiohttp>=3.9.0",
        "sseclient>=0.0.27"
    ],
    entry_points={
        "console_scripts": [
            "mcp-scan=scanner.cli:scan",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    keywords="mcp, security, scanner, vulnerability, ai, ollama, openai, gemini, secrets",
    project_urls={
        "Bug Reports": "https://github.com/DataDruide/mcp-vuln-scanner/issues",
        "Source": "https://github.com/DataDruide/mcp-vuln-scanner",
        "Documentation": "https://github.com/DataDruide/mcp-vuln-scanner#readme",
    },
)
