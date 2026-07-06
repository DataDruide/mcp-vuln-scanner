import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Dict, Any
from datetime import datetime

def send_email_report(findings: Dict[str, Any], to_email: str, subject: str = None, attachment: str = None):
    """Sendet einen Email-Bericht mit Findings"""
    
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    
    if not smtp_user or not smtp_password:
        print("❌ Email nicht konfiguriert. Setze SMTP_USER und SMTP_PASSWORD")
        return False
    
    # Bericht generieren
    dangerous = findings.get("dangerous", [])
    poisoning = findings.get("poisoning", [])
    secrets = findings.get("secrets", [])
    
    subject = subject or f"MCP Security Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .critical {{ color: #dc3545; }}
            .high {{ color: #fd7e14; }}
            .medium {{ color: #ffc107; }}
            .finding {{ background: #f8f9fa; padding: 10px; margin: 10px 0; border-left: 4px solid; }}
        </style>
    </head>
    <body>
        <h1>🔒 MCP Security Scanner Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>📊 Summary</h2>
        <ul>
            <li>⚠️ Dangerous Operations: {len(dangerous)}</li>
            <li>🎭 Tool Poisoning: {len(poisoning)}</li>
            <li>🔑 Secrets Found: {len(secrets)}</li>
        </ul>
        
        <h2>⚠️ Dangerous Operations</h2>
        {''.join([f'<div class="finding"><strong>{f.tool_name}</strong> [{f.risk_level.value}]: {f.description}<br><small>Fix: {f.remediation}</small></div>' for f in dangerous[:10]])}
        
        <h2>🎭 Tool Poisoning</h2>
        {''.join([f'<div class="finding"><strong>{f.tool_name}</strong> [{f.poisoning_type}]: {f.description}</div>' for f in poisoning[:10]])}
        
        <h2>🔑 Secrets Found</h2>
        {''.join([f'<div class="finding"><strong>{f.tool_name}</strong> [{f.severity}]: {f.description}</div>' for f in secrets[:10]])}
        
        <hr>
        <p><small>MCP Vulnerability Scanner v1.1.0 | <a href="https://github.com/DataDruide/mcp-vuln-scanner">GitHub</a></small></p>
    </body>
    </html>
    """
    
    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(html, 'html'))
    
    # Attachment hinzufügen
    if attachment and os.path.exists(attachment):
        with open(attachment, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment)}"')
            msg.attach(part)
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"❌ Email Fehler: {e}")
        return False
