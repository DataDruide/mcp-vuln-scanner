"""
Web Dashboard for MCP Security Scanner.

Provides a Flask-based web interface for viewing scan results,
trend analysis, and threat intelligence database.
"""
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file
import os


class ScanResultsStore:
    """Store and retrieve scan results."""

    def __init__(self, storage_dir: Optional[Path] = None):
        """Initialize results storage.
        
        Args:
            storage_dir: Directory to store scan results. 
                        Defaults to ~/.mcp-scanner/results/
        """
        if storage_dir is None:
            storage_dir = Path.home() / ".mcp-scanner" / "results"
        
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def save_scan(self, tool_name: str, findings: Dict[str, Any]) -> str:
        """Save scan results.
        
        Args:
            tool_name: Name of tool being scanned
            findings: Dictionary of findings
            
        Returns:
            Scan ID
        """
        scan_id = datetime.now().isoformat().replace(":", "-")
        scan_file = self.storage_dir / f"scan_{scan_id}_{tool_name}.json"
        
        data = {
            "scan_id": scan_id,
            "tool": tool_name,
            "timestamp": datetime.now().isoformat(),
            "findings": findings
        }
        
        scan_file.write_text(json.dumps(data, indent=2))
        return scan_id

    def get_scans(self) -> List[Dict[str, Any]]:
        """Get all stored scans.
        
        Returns:
            List of scan records
        """
        scans = []
        for scan_file in sorted(self.storage_dir.glob("scan_*.json"), reverse=True):
            try:
                data = json.loads(scan_file.read_text())
                scans.append(data)
            except Exception:
                pass
        return scans

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get specific scan by ID.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Scan data or None if not found
        """
        for scan_file in self.storage_dir.glob(f"*{scan_id}*.json"):
            try:
                return json.loads(scan_file.read_text())
            except Exception:
                pass
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored scans.
        
        Returns:
            Statistics dictionary
        """
        scans = self.get_scans()
        
        total_dangerous = sum(
            len(scan["findings"].get("dangerous", []))
            for scan in scans
        )
        total_secrets = sum(
            len(scan["findings"].get("secrets", []))
            for scan in scans
        )
        total_threats = sum(
            len(scan["findings"].get("threats", []))
            for scan in scans
        )
        
        return {
            "total_scans": len(scans),
            "total_dangerous_findings": total_dangerous,
            "total_secrets_found": total_secrets,
            "total_threats_detected": total_threats,
            "last_scan": scans[0]["timestamp"] if scans else None
        }


class DashboardServer:
    """Flask-based web dashboard for scan results."""

    def __init__(self, port: int = 5000, storage_dir: Optional[Path] = None):
        """Initialize dashboard server.
        
        Args:
            port: Port to run server on
            storage_dir: Directory for storing results
        """
        self.port = port
        
        # Get template and static directories
        current_dir = Path(__file__).parent.parent.parent  # Project root
        template_dir = current_dir / "templates"
        static_dir = current_dir / "static"
        
        self.app = Flask(
            __name__,
            template_folder=str(template_dir),
            static_folder=str(static_dir)
        )
        self.store = ScanResultsStore(storage_dir)
        
        self._register_routes()

    def _register_routes(self) -> None:
        """Register Flask routes."""

        @self.app.route("/")
        def index():
            """Dashboard home page."""
            stats = self.store.get_statistics()
            return render_template("index.html", stats=stats)

        @self.app.route("/api/scans")
        def get_scans():
            """Get all scans as JSON."""
            scans = self.store.get_scans()
            return jsonify(scans)

        @self.app.route("/api/scans/<scan_id>")
        def get_scan(scan_id):
            """Get specific scan."""
            scan = self.store.get_scan(scan_id)
            if scan:
                return jsonify(scan)
            return jsonify({"error": "Scan not found"}), 404

        @self.app.route("/api/statistics")
        def get_statistics():
            """Get statistics."""
            return jsonify(self.store.get_statistics())

        @self.app.route("/api/threats")
        def get_threats():
            """Get all threats from all scans."""
            scans = self.store.get_scans()
            threats = []
            for scan in scans:
                for threat in scan["findings"].get("threats", []):
                    threat["scan_id"] = scan["scan_id"]
                    threat["scan_time"] = scan["timestamp"]
                    threats.append(threat)
            return jsonify(threats)

        @self.app.route("/api/dangerous")
        def get_dangerous():
            """Get all dangerous findings."""
            scans = self.store.get_scans()
            findings = []
            for scan in scans:
                for finding in scan["findings"].get("dangerous", []):
                    if isinstance(finding, dict):
                        finding["scan_id"] = scan["scan_id"]
                        finding["scan_time"] = scan["timestamp"]
                        findings.append(finding)
            return jsonify(findings)

        @self.app.route("/api/export/<scan_id>")
        def export_scan(scan_id):
            """Export scan as JSON file."""
            scan = self.store.get_scan(scan_id)
            if not scan:
                return jsonify({"error": "Scan not found"}), 404
            
            # Create temporary file
            temp_file = Path(f"/tmp/scan_{scan_id}.json")
            temp_file.write_text(json.dumps(scan, indent=2))
            
            return send_file(
                temp_file,
                as_attachment=True,
                download_name=f"scan_{scan_id}.json"
            )

        @self.app.errorhandler(404)
        def not_found(error):
            """Handle 404 errors."""
            return jsonify({"error": "Not found"}), 404

        @self.app.errorhandler(500)
        def server_error(error):
            """Handle 500 errors."""
            return jsonify({"error": "Server error"}), 500

    def run(self, debug: bool = False) -> None:
        """Run the dashboard server.
        
        Args:
            debug: Whether to run in debug mode
        """
        print(f"🚀 MCP Security Dashboard running on http://localhost:{self.port}")
        print(f"📊 Open browser to view results")
        self.app.run(host="0.0.0.0", port=self.port, debug=debug)


def create_app(storage_dir: Optional[Path] = None) -> Flask:
    """Create and configure Flask app.
    
    Args:
        storage_dir: Directory for storing results
        
    Returns:
        Configured Flask app
    """
    dashboard = DashboardServer(storage_dir=storage_dir)
    return dashboard.app


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="MCP Security Dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Port to run on")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    parser.add_argument("--storage", type=Path, help="Results storage directory")
    
    args = parser.parse_args()
    
    server = DashboardServer(port=args.port, storage_dir=args.storage)
    server.run(debug=args.debug)
