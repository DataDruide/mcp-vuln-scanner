# Web Dashboard

## Overview

The MCP Security Dashboard provides a real-time web interface for viewing and analyzing scan results. Monitor security findings, track threats, and visualize trends across your MCP tool infrastructure.

## Features

- **Real-Time Monitoring**: View latest scan results as they complete
- **Interactive Charts**: Visualize findings by category and severity
- **Threat Tracking**: Monitor detected threats in a timeline
- **Result History**: Browse all past scans with detailed information
- **Export Capabilities**: Download scan results as JSON
- **Responsive Design**: Works on desktop, tablet, and mobile

## Installation

### Prerequisites

- Python 3.9+
- Flask 2.3+
- Modern web browser

### Setup

1. **Install Flask** (if not already installed):
   ```bash
   pip install flask
   ```

2. **Update MCP Scanner**:
   ```bash
   cd mcp-security-scanner
   pip install -e .
   ```

## Running the Dashboard

### Start the Dashboard Server

```bash
python -m scanner.dashboard --port 5000
```

The dashboard will be available at: `http://localhost:5000`

### Configuration Options

```bash
# Run on custom port
python -m scanner.dashboard --port 8080

# Debug mode (auto-reload)
python -m scanner.dashboard --debug

# Custom storage directory
python -m scanner.dashboard --storage ~/.mcp-scanner/custom-results
```

## Usage

### Dashboard Home

The home page shows:
- **Statistics Cards**: Total scans, dangerous findings, secrets, threats
- **Findings Chart**: Bar chart of all finding types
- **Severity Distribution**: Doughnut chart of threat severity levels

### Recent Scans

View the 10 most recent scans with:
- Tool name and timestamp
- Finding counts (dangerous, secrets, threats, poisoning)
- Export button for detailed JSON report

### Active Threats

List of all detected threats with:
- Threat name and severity level
- Affected tool
- Threat category
- Indicator matched
- Confidence score

### API Endpoints

All dashboard data is available via REST API:

#### Get All Scans

```bash
curl http://localhost:5000/api/scans
```

Response:
```json
[
  {
    "scan_id": "2024-07-06T10-30-45.123456",
    "tool": "tools.json",
    "timestamp": "2024-07-06T10:30:45.123456",
    "findings": {
      "dangerous": [...],
      "secrets": [...],
      "threats": [...]
    }
  }
]
```

#### Get Specific Scan

```bash
curl http://localhost:5000/api/scans/{scan_id}
```

#### Get Statistics

```bash
curl http://localhost:5000/api/statistics
```

Response:
```json
{
  "total_scans": 42,
  "total_dangerous_findings": 128,
  "total_secrets_found": 15,
  "total_threats_detected": 8,
  "last_scan": "2024-07-06T10:30:45.123456"
}
```

#### Get All Threats

```bash
curl http://localhost:5000/api/threats
```

#### Get Dangerous Findings

```bash
curl http://localhost:5000/api/dangerous
```

#### Export Scan

```bash
curl http://localhost:5000/api/export/{scan_id} > scan.json
```

## Integration with MCP Scan

### Automatic Result Storage

Results are automatically stored when using the scanner:

```bash
# Results stored in ~/.mcp-scanner/results/
mcp-scan tools.json --format json
```

### Accessing Results

Results are stored as JSON files in:
- **Linux/macOS**: `~/.mcp-scanner/results/`
- **Windows**: `%USERPROFILE%\.mcp-scanner\results\`

### Custom Storage Location

```bash
# Set custom storage in environment
export MCP_SCANNER_STORAGE="/var/log/mcp-scans"

# Or specify in code
from scanner.dashboard import ScanResultsStore
from pathlib import Path

store = ScanResultsStore(Path("/custom/path"))
```

## Features in Detail

### Real-Time Updates

The dashboard automatically refreshes scan data every 30 seconds:

```javascript
// Auto-refresh every 30 seconds
setInterval(function() {
    loadScans();
    loadThreats();
}, 30000);
```

### Interactive Charts

- **Findings Chart**: Shows count of each finding type
- **Severity Distribution**: Shows threat breakdown by severity
- Both charts are responsive and update automatically

### Scan Details

Each scan shows:
- Tool name
- Scan timestamp
- Dangerous findings count
- Secrets found count
- Threats detected count
- Poisoning indicators count

### Export Functionality

Export individual scans as JSON:

```bash
# Download via web UI
# Click "📥 Export" button on any scan

# Or via API
curl http://localhost:5000/api/export/{scan_id} > results.json
```

## Advanced Usage

### Custom Storage Directory

```python
from scanner.dashboard import DashboardServer, ScanResultsStore
from pathlib import Path

# Use custom storage
storage = Path("/var/log/mcp-security")
server = DashboardServer(port=5000, storage_dir=storage)
server.run()
```

### Programmatic Scan Storage

```python
from scanner.dashboard import ScanResultsStore
from pathlib import Path

store = ScanResultsStore()

# Save scan results
scan_id = store.save_scan("my_tool", findings)

# Retrieve later
scan = store.get_scan(scan_id)

# Get statistics
stats = store.get_statistics()
```

### Integration with CI/CD

Store CI/CD scan results for historical analysis:

```bash
#!/bin/bash
# ci-scan.sh

SCAN_RESULTS=$(mcp-scan tools.json --format json)

# Store results for dashboard
python -c "
from scanner.dashboard import ScanResultsStore
import json
import sys

store = ScanResultsStore()
findings = json.loads('$SCAN_RESULTS')
scan_id = store.save_scan('ci-build', findings)
print(f'Scan stored: {scan_id}')
"
```

## Troubleshooting

### Port Already in Use

```bash
# Use different port
python -m scanner.dashboard --port 8080

# Or find and kill process using port
lsof -i :5000
kill -9 <PID>
```

### Templates Not Found

Ensure templates are in correct location:

```
templates/
  ├── index.html
static/
  ├── style.css
  └── dashboard.js
```

### Data Not Persisting

By default, results are stored in `~/.mcp-scanner/results/`. Ensure:
- Directory exists and is writable
- Sufficient disk space available
- Permissions are correct

### Charts Not Loading

Check browser console for errors. Ensure Chart.js CDN is accessible:

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
```

## Performance Considerations

- Dashboard stores scan results locally (no database required)
- Results are JSON files in filesystem
- Scales to thousands of scans
- API responses are computed in-memory from stored files

### Optimization Tips

1. **Archive Old Results**: Periodically backup old scan files
2. **Custom Storage**: Use fast storage (SSD) for better performance
3. **Cleanup**: Remove very old scan files to save space
4. **Monitoring**: Monitor disk usage in storage directory

## Security Considerations

- Dashboard server listens on localhost by default
- No authentication built-in (add reverse proxy for security)
- Results contain sensitive information (store securely)
- HTTPS recommended for production deployments

### Production Deployment

For production use, consider:

1. **Reverse Proxy** (nginx/Apache):
   ```nginx
   location /dashboard {
       proxy_pass http://localhost:5000;
       ssl_certificate /path/to/cert;
   }
   ```

2. **Authentication** (OAuth2/SSO):
   ```python
   from flask_oauth import OAuth
   # Add authentication middleware
   ```

3. **Persistent Storage**:
   ```bash
   # Use mounted volume
   docker run -v /secure/storage:/data ...
   ```

4. **Monitoring**:
   ```bash
   # Monitor dashboard health
   curl http://localhost:5000/api/statistics
   ```

## Roadmap

Planned enhancements:

- [ ] User authentication and multi-user support
- [ ] Custom dashboards and widgets
- [ ] Advanced filtering and search
- [ ] Automated alert notifications
- [ ] Trend analysis and predictions
- [ ] Integration with SIEM systems
- [ ] PDF report generation
- [ ] Database backend option
