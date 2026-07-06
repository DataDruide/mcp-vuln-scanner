import json
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory
from src.scanner.dashboard import ScanResultsStore, DashboardServer


def test_scan_results_store_save():
    """Test saving scan results."""
    with TemporaryDirectory() as tmpdir:
        store = ScanResultsStore(Path(tmpdir))
        
        findings = {
            "dangerous": [],
            "secrets": [],
            "threats": [
                {"threat_name": "Test Threat", "severity": "high"}
            ]
        }
        
        scan_id = store.save_scan("test_tool", findings)
        assert scan_id is not None
        assert len(store.get_scans()) == 1


def test_scan_results_store_retrieve():
    """Test retrieving scan results."""
    with TemporaryDirectory() as tmpdir:
        store = ScanResultsStore(Path(tmpdir))
        
        findings = {
            "dangerous": [{"tool": "test"}],
            "secrets": [],
            "threats": []
        }
        
        scan_id = store.save_scan("test_tool", findings)
        scan = store.get_scan(scan_id)
        
        assert scan is not None
        assert scan["tool"] == "test_tool"
        assert len(scan["findings"]["dangerous"]) == 1


def test_scan_results_store_statistics():
    """Test generating statistics."""
    with TemporaryDirectory() as tmpdir:
        store = ScanResultsStore(Path(tmpdir))
        
        # Add multiple scans
        for i in range(3):
            findings = {
                "dangerous": [{"id": j} for j in range(i + 1)],
                "secrets": [{"id": j} for j in range(i)],
                "threats": []
            }
            store.save_scan(f"tool_{i}", findings)
        
        stats = store.get_statistics()
        
        assert stats["total_scans"] == 3
        assert stats["total_dangerous_findings"] == 6  # 1 + 2 + 3
        assert stats["total_secrets_found"] == 3  # 0 + 1 + 2


def test_dashboard_server_initialization():
    """Test dashboard server initialization."""
    with TemporaryDirectory() as tmpdir:
        server = DashboardServer(port=5001, storage_dir=Path(tmpdir))
        assert server.app is not None
        assert server.port == 5001
        assert server.store is not None


def test_dashboard_api_routes():
    """Test dashboard API routes."""
    with TemporaryDirectory() as tmpdir:
        server = DashboardServer(port=5002, storage_dir=Path(tmpdir))
        
        with server.app.test_client() as client:
            # Test home page
            response = client.get('/')
            assert response.status_code == 200
            
            # Test statistics API
            response = client.get('/api/statistics')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'total_scans' in data
            
            # Test scans API
            response = client.get('/api/scans')
            assert response.status_code == 200
            assert isinstance(json.loads(response.data), list)
            
            # Test threats API
            response = client.get('/api/threats')
            assert response.status_code == 200
            assert isinstance(json.loads(response.data), list)


def test_dashboard_scan_details():
    """Test retrieving specific scan details."""
    with TemporaryDirectory() as tmpdir:
        store = ScanResultsStore(Path(tmpdir))
        server = DashboardServer(port=5003, storage_dir=Path(tmpdir))
        
        findings = {
            "dangerous": [{"tool": "test", "severity": "high"}],
            "secrets": [],
            "threats": [{"threat_name": "Test", "severity": "critical"}]
        }
        
        scan_id = store.save_scan("test_tool", findings)
        
        with server.app.test_client() as client:
            response = client.get(f'/api/scans/{scan_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["tool"] == "test_tool"
