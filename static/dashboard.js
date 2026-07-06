// Load data and initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    loadScans();
    loadThreats();
    loadCharts();
    
    // Refresh data every 30 seconds
    setInterval(function() {
        loadScans();
        loadThreats();
    }, 30000);
});

// Load scans and display them
async function loadScans() {
    try {
        const response = await fetch('/api/scans');
        const scans = await response.json();
        
        const scansList = document.getElementById('scans-list');
        
        if (scans.length === 0) {
            scansList.innerHTML = '<p class="loading">No scans yet. Run "mcp-scan" to generate data.</p>';
            return;
        }
        
        scansList.innerHTML = scans.slice(0, 10).map(scan => `
            <div class="scan-item ${getSeverityClass(scan.findings)}">
                <div class="scan-item-header">
                    <span class="scan-item-title">📁 ${scan.tool}</span>
                    <span class="scan-item-time">${formatTime(scan.timestamp)}</span>
                </div>
                <div class="scan-item-details">
                    <div class="detail">
                        <span class="detail-label">Dangerous:</span>
                        <span class="detail-value">${scan.findings.dangerous?.length || 0}</span>
                    </div>
                    <div class="detail">
                        <span class="detail-label">Secrets:</span>
                        <span class="detail-value">${scan.findings.secrets?.length || 0}</span>
                    </div>
                    <div class="detail">
                        <span class="detail-label">Threats:</span>
                        <span class="detail-value">${scan.findings.threats?.length || 0}</span>
                    </div>
                    <div class="detail">
                        <span class="detail-label">Poisoning:</span>
                        <span class="detail-value">${scan.findings.poisoning?.length || 0}</span>
                    </div>
                </div>
                <button onclick="exportScan('${scan.scan_id}')" style="margin-top: 10px; padding: 8px 16px; background: #0d47a1; color: white; border: none; border-radius: 4px; cursor: pointer;">
                    📥 Export
                </button>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading scans:', error);
    }
}

// Load threats and display them
async function loadThreats() {
    try {
        const response = await fetch('/api/threats');
        const threats = await response.json();
        
        const threatsList = document.getElementById('threats-list-content');
        
        if (threats.length === 0) {
            threatsList.innerHTML = '<p class="loading">✅ No threats detected.</p>';
            return;
        }
        
        threatsList.innerHTML = threats.slice(0, 10).map(threat => `
            <div class="threat-item">
                <div class="scan-item-header">
                    <span class="scan-item-title">🚨 ${threat.threat_name}</span>
                    <span class="threat-severity ${threat.severity.toLowerCase()}">${threat.severity}</span>
                </div>
                <div class="scan-item-details">
                    <div class="detail">
                        <span class="detail-label">Tool:</span>
                        <span class="detail-value">${threat.tool_name}</span>
                    </div>
                    <div class="detail">
                        <span class="detail-label">Category:</span>
                        <span class="detail-value">${threat.category}</span>
                    </div>
                    <div class="detail">
                        <span class="detail-label">Indicator:</span>
                        <span class="detail-value">${threat.indicator}</span>
                    </div>
                    <div class="detail">
                        <span class="detail-label">Confidence:</span>
                        <span class="detail-value">${(threat.confidence * 100).toFixed(0)}%</span>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading threats:', error);
    }
}

// Load and initialize charts
async function loadCharts() {
    try {
        const response = await fetch('/api/scans');
        const scans = await response.json();
        
        // Aggregate findings
        let dangerousCount = 0;
        let secretsCount = 0;
        let threatsCount = 0;
        let poisoningCount = 0;
        
        const severityCount = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        scans.forEach(scan => {
            dangerousCount += scan.findings.dangerous?.length || 0;
            secretsCount += scan.findings.secrets?.length || 0;
            threatsCount += scan.findings.threats?.length || 0;
            poisoningCount += scan.findings.poisoning?.length || 0;
            
            // Count threat severity
            (scan.findings.threats || []).forEach(threat => {
                const sev = threat.severity?.toLowerCase() || 'low';
                if (sev in severityCount) {
                    severityCount[sev]++;
                }
            });
        });
        
        // Findings chart
        const findingsCtx = document.getElementById('findingsChart');
        if (findingsCtx) {
            new Chart(findingsCtx, {
                type: 'bar',
                data: {
                    labels: ['Dangerous', 'Secrets', 'Threats', 'Poisoning'],
                    datasets: [{
                        label: 'Findings',
                        data: [dangerousCount, secretsCount, threatsCount, poisoningCount],
                        backgroundColor: [
                            '#0d47a1',
                            '#c62828',
                            '#6a1b9a',
                            '#f57c00'
                        ],
                        borderRadius: 5,
                        borderSkipped: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            }
                        }
                    }
                }
            });
        }
        
        // Threats severity chart
        const threatsCtx = document.getElementById('threatsChart');
        if (threatsCtx) {
            new Chart(threatsCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [
                            severityCount.critical,
                            severityCount.high,
                            severityCount.medium,
                            severityCount.low
                        ],
                        backgroundColor: [
                            '#6a1b9a',
                            '#f57c00',
                            '#fbc02d',
                            '#0d47a1'
                        ],
                        borderColor: '#fff',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error loading charts:', error);
    }
}

// Get severity class for scan item
function getSeverityClass(findings) {
    const threatening = findings.threats?.length || 0;
    const secrets = findings.secrets?.length || 0;
    const dangerous = findings.dangerous?.length || 0;
    
    if (threatening > 0) return 'critical';
    if (secrets > 0) return 'danger';
    if (dangerous > 0) return 'warning';
    return '';
}

// Format time for display
function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins} min ago`;
    if (diffHours < 24) return `${diffHours} hours ago`;
    if (diffDays < 7) return `${diffDays} days ago`;
    
    return date.toLocaleDateString();
}

// Export scan as JSON
function exportScan(scanId) {
    window.location.href = `/api/export/${scanId}`;
}
