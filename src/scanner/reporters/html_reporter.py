# src/scanner/reporters/html_reporter.py
import json
from datetime import datetime
from typing import List, Dict, Any
from ..analyzers.dangerous_ops import RiskLevel

class HtmlReporter:
    """Generiert hübsche HTML-Berichte mit Charts"""
    
    def generate(self, findings: Dict[str, List], score=None) -> str:
        """Erstellt einen HTML-Bericht"""
        
        # Zähle Findings nach Severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings.get("dangerous", []):
            severity_counts[f.risk_level.value] += 1
        
        html = f"""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Security Scanner - Bericht</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        .content {{ padding: 40px; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            transition: transform 0.3s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{ color: #666; margin-top: 10px; }}
        .chart-container {{
            width: 300px;
            margin: 20px auto;
        }}
        .finding {{
            background: #f8f9fa;
            border-left: 4px solid;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 8px;
            transition: all 0.3s;
        }}
        .finding:hover {{ box-shadow: 0 5px 15px rgba(0,0,0,0.1); }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding-title {{
            font-weight: bold;
            font-size: 1.1em;
            margin-bottom: 8px;
        }}
        .finding-description {{ color: #666; margin-bottom: 8px; }}
        .finding-remediation {{
            background: #e9ecef;
            padding: 8px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.9em;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: bold;
            margin-left: 10px;
        }}
        .badge.critical {{ background: #dc3545; color: white; }}
        .badge.high {{ background: #fd7e14; color: white; }}
        .badge.medium {{ background: #ffc107; color: #333; }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        @media (max-width: 768px) {{
            .stats {{ grid-template-columns: 1fr; }}
            .content {{ padding: 20px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 MCP Security Scanner</h1>
            <p>Sicherheitsbericht für MCP-Server</p>
            <p><small>{datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</small></p>
        </div>
        
        <div class="content">
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{len(findings.get('dangerous', []))}</div>
                    <div class="stat-label">⚠️ Gefährliche Operationen</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(findings.get('poisoning', []))}</div>
                    <div class="stat-label">🎭 Tool-Poisoning-Verdacht</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{severity_counts['critical']}</div>
                    <div class="stat-label">🔴 Kritisch</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{severity_counts['high']}</div>
                    <div class="stat-label">🟠 Hoch</div>
                </div>
            </div>
            
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
            
            <h2>⚠️ Gefährliche Operationen</h2>
            {self._generate_finding_html(findings.get('dangerous', []))}
            
            <h2 style="margin-top: 30px;">🎭 Tool-Poisoning-Verdacht</h2>
            {self._generate_poisoning_html(findings.get('poisoning', []))}
        </div>
        
        <div class="footer">
            <p>MCP Security Scanner v0.2.0 | Bericht automatisch generiert</p>
        </div>
    </div>
    
    <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Kritisch', 'Hoch', 'Mittel', 'Niedrig'],
                datasets: [{{
                    data: [{severity_counts['critical']}, {severity_counts['high']}, {severity_counts['medium']}, {severity_counts['low']}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        return html
    
    def _generate_finding_html(self, findings: List) -> str:
        """Generiert HTML für Findings"""
        if not findings:
            return '<p>✅ Keine gefährlichen Operationen gefunden.</p>'
        
        html = ""
        for f in findings:
            severity_class = f.risk_level.value
            html += f"""
            <div class="finding {severity_class}">
                <div class="finding-title">
                    {f.tool_name}
                    <span class="badge {severity_class}">{f.risk_level.value.upper()}</span>
                </div>
                <div class="finding-description">{f.description}</div>
                <div class="finding-description"><strong>Ort:</strong> {f.location}</div>
                <div class="finding-remediation">🔧 {f.remediation}</div>
                {f'<div><strong>CWE:</strong> {f.cwe_id}</div>' if f.cwe_id else ''}
            </div>"""
        
        return html
    
    def _generate_poisoning_html(self, findings: List) -> str:
        """Generiert HTML für Poisoning-Findings"""
        if not findings:
            return '<p>✅ Keine Tool-Poisoning-Verdachtsfälle gefunden.</p>'
        
        html = ""
        for f in findings:
            confidence_percent = f"{f.confidence:.0%}"
            html += f"""
            <div class="finding">
                <div class="finding-title">
                    {f.tool_name}
                    <span class="badge">Vertrauen: {confidence_percent}</span>
                </div>
                <div class="finding-description">
                    <strong>Typ:</strong> {f.poisoning_type}<br>
                    {f.description}
                </div>
                {f'<div class="finding-remediation">💡 Alternative: {f.suggested_alternative}</div>' if f.suggested_alternative else ''}
            </div>"""
        
        return html
