import click
import json
from pathlib import Path
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.analyzers.dangerous_ops import DangerousOperationAnalyzer, RiskLevel
from scanner.analyzers.tool_poisoning import ToolPoisoningDetector
from scanner.reporters.sarif_reporter import SarifReporter
from scanner.reporters.html_reporter import HtmlReporter
from scanner.plugin import PluginManager, AnalyzerPlugin, ReporterPlugin
from scanner.ai_fixer import AIFixer
from scanner.notify import send_slack_alert, send_jira_issue
from scanner.secret_detector import SecretDetector
from scanner.email_reporter import send_email_report
from scanner.discord_notify import send_discord_alert

@click.command()
@click.argument("target", required=True)
@click.option("--format", "-f", type=click.Choice(["json", "sarif", "html", "console"]), default="console", help="Ausgabeformat")
@click.option("--output", "-o", type=Path, help="Ausgabedatei")
@click.option("--severity", "-s", multiple=True, type=click.Choice(["critical", "high", "medium", "low", "info"]), help="Nur Findings mit dieser Severity")
@click.option("--verbose", "-v", is_flag=True, help="Ausführliche Ausgabe")
@click.option("--fix", is_flag=True, help="AI-gestützte Fix-Vorschläge generieren")
@click.option("--apply", is_flag=True, help="AI-Fixes automatisch anwenden und speichern")
@click.option("--dry-run", is_flag=True, help="Nur Anzeigen der Fixes, nicht anwenden")
@click.option("--git-patch", is_flag=True, help="Gib einen unified diff (git patch) der Änderungen aus")
@click.option("--slack", help="Slack Webhook URL für Benachrichtigungen")
@click.option("--jira", is_flag=True, help="Jira-Tickets für kritische Findings erstellen")
@click.option("--secrets", is_flag=True, help="Secret Detection (API-Keys, Passwörter)")
@click.option("--email", help="Email-Adresse für Bericht")
@click.option("--discord", help="Discord Webhook URL für Benachrichtigungen")
@click.option("--github", is_flag=True, help="Emit GitHub Actions annotations (workflow commands)")
@click.option("--fail-level", type=click.Choice(["none", "info", "low", "medium", "high", "critical"]), default="high", help="CI fail level: fail if findings >= this level")
@click.option("--sbom", type=Path, help="Generiere SBOM aus requirements.txt und speichere nach Pfad")
@click.option("--vuln-db", type=Path, help="Pfad zur einfachen Vulnerability-DB (JSON)")
def scan(target, format, output, severity, verbose, fix, apply, dry_run, git_patch, slack, jira, secrets, email, discord, github, fail_level, sbom, vuln_db):
    click.echo(f"🔍 MCP Vulnerability Scanner - Scan startet für: {target}\n")
    
    if target == "example":
        tools = get_example_tools()
        click.echo("📦 Verwende Beispiel-Tools für Demo\n")
    else:
        try:
            with open(target, 'r') as f:
                data = json.load(f)
                tools = data.get("tools", [])
            click.echo(f"📦 Gefunden: {len(tools)} Tools\n")
        except Exception as e:
            if sbom:
                click.echo(f"ℹ️ Zieldatei ist keine tools.json; fortfahre für SBOM: {e}")
                tools = []
            else:
                click.echo(f"❌ Fehler: {e}", err=True)
                return 1
    
    all_findings = {"dangerous": [], "poisoning": [], "secrets": []}
    # Load plugins (external) and fall back to built-in analyzers
    pm = PluginManager()
    analyzers, reporters = pm.discover()

    # instantiate built-ins if no plugins provided that role
    dangerous_analyzer = next((a for a in analyzers if isinstance(a, AnalyzerPlugin) and a.__class__.__name__ == 'DangerousOperationAnalyzer'), None)
    if dangerous_analyzer is None:
        dangerous_analyzer = DangerousOperationAnalyzer()

    poisoning_detector = next((a for a in analyzers if a.__class__.__name__ == 'ToolPoisoningDetector'), None)
    if poisoning_detector is None:
        poisoning_detector = ToolPoisoningDetector()

    secret_detector = next((a for a in analyzers if a.__class__.__name__ == 'SecretDetector'), None)
    if secret_detector is None:
        secret_detector = SecretDetector()
    
    if verbose:
        click.echo("🔬 Führe Analysen durch...")
    
    for tool in tools:
        if verbose:
            click.echo(f"  Analysiere Tool: {tool.get('name', 'unknown')}")
        all_findings["dangerous"].extend(dangerous_analyzer.analyze(tool))
        
        if secrets:
            all_findings["secrets"].extend(secret_detector.analyze(tool))
    
    all_findings["poisoning"] = poisoning_detector.analyze(tools)
    
    if severity:
        severity_values = set(severity)
        all_findings["dangerous"] = [f for f in all_findings["dangerous"] if f.risk_level.value in severity_values]
        all_findings["secrets"] = [f for f in all_findings["secrets"] if f.severity in severity_values]
    
    if fix:
        click.echo("\n🤖 Generiere AI-Fix-Vorschläge...")
        fixer = AIFixer()
        fixes = []
        for f in all_findings["dangerous"]:
            suggestion = fixer.generate_fix(f)
            click.echo(f"\n  🔧 {f.tool_name} ({f.risk_level.value}):")
            click.echo(f"     {suggestion[:300]}{'...' if len(suggestion) > 300 else ''}")
            fixes.append((f, suggestion))
        
        if apply:
            click.echo("\n🔧 Wende Fixes an...")
            # try to load existing tools.json; if not JSON, assume target may be requirements for sbom
            original_tools = []
            try:
                with open(target, 'r') as f:
                    data = json.load(f)
                    original_tools = data.get("tools", [])
            except Exception:
                # no tools.json — fall back to empty list
                original_tools = []

            import copy
            updated_tools = copy.deepcopy(original_tools)
            patches = []
            fixed_count = 0
            for idx, tool in enumerate(updated_tools):
                for finding, suggestion in fixes:
                    if tool.get("name") == finding.tool_name:
                        orig_tool = copy.deepcopy(tool)
                        success, updated_tool = fixer.apply_fix(tool, finding, suggestion)
                        if success:
                            updated_tools[idx] = updated_tool
                            fixed_count += 1
                            click.echo(f"   ✅ {finding.tool_name} gefixt")
                            if git_patch:
                                patch_text = fixer.generate_patch(orig_tool, updated_tool)
                                patches.append((finding.tool_name, patch_text))
                        break

            if git_patch and patches:
                click.echo("\n--- Git Patch Output ---")
                for name, ptext in patches:
                    click.echo(f"# Patch for {name}")
                    click.echo(ptext)

            if dry_run:
                click.echo(f"\nℹ️ Dry-run: {fixed_count} Änderungen simuliert; keine Dateien geschrieben.")
            else:
                import shutil
                backup = str(target) + ".backup"
                try:
                    shutil.copy(str(target), backup)
                    click.echo(f"   💾 Backup gespeichert: {backup}")
                except Exception:
                    # ignore backup errors
                    pass

                try:
                    with open(target, 'w') as f:
                        json.dump({"tools": updated_tools}, f, indent=2)
                    click.echo(f"   💾 Gefixte Datei gespeichert: {target}")
                    click.echo(f"\n✅ {fixed_count} Tools wurden automatisch gefixt!")
                except Exception as e:
                    click.echo(f"   ❌ Fehler beim Schreiben der gefixten Datei: {e}")

    # SBOM & Dependency-Scanning
    if sbom:
        click.echo(f"\n📦 Generiere SBOM aus: {target}")
        try:
            from scanner.sbom import generate_sbom_from_requirements, check_vulnerabilities_from_db
            sbom_content = generate_sbom_from_requirements(str(target))
            Path(sbom).write_text(sbom_content)
            click.echo(f"   ✅ SBOM gespeichert: {sbom}")
            if vuln_db:
                findings = check_vulnerabilities_from_db(sbom_content, str(vuln_db))
                if findings:
                    click.echo(f"   ⚠️ {len(findings)} verwundbare Abhängigkeiten gefunden")
                    for f in findings:
                        click.echo(f"     - {f['package']}=={f['version']}: {f['description']}")
                    # fail if any vulnerable deps
                    sys.exit(1)
                else:
                    click.echo("   ✅ Keine verwundbaren Abhängigkeiten gefunden")
        except Exception as e:
            click.echo(f"   ❌ SBOM-Fehler: {e}")
    
    if slack:
        click.echo("\n📢 Sende Slack-Benachrichtigung...")
        if send_slack_alert(all_findings["dangerous"], slack):
            click.echo("   ✅ Slack-Benachrichtigung gesendet")
        else:
            click.echo("   ❌ Slack-Benachrichtigung fehlgeschlagen")
    
    if discord:
        click.echo("\n🎮 Sende Discord-Benachrichtigung...")
        if send_discord_alert(all_findings, discord):
            click.echo("   ✅ Discord-Benachrichtigung gesendet")
        else:
            click.echo("   ❌ Discord-Benachrichtigung fehlgeschlagen")
    
    if email:
        click.echo("\n📧 Sende Email-Bericht...")
        if output:
            attachment = str(output) if output.exists() else None
        else:
            attachment = None
        if send_email_report(all_findings, email, attachment=attachment):
            click.echo(f"   ✅ Email an {email} gesendet")
        else:
            click.echo("   ❌ Email fehlgeschlagen")
    
    if jira:
        click.echo("\n📋 Erstelle Jira-Tickets für kritische Findings...")
        critical = [f for f in all_findings["dangerous"] if f.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
        for f in critical[:5]:
            if send_jira_issue(f):
                click.echo(f"   ✅ Ticket für {f.tool_name} erstellt")
            else:
                click.echo(f"   ❌ Ticket für {f.tool_name} fehlgeschlagen")
    
    score = None
    if format == "json":
        report = generate_json_report(all_findings)
    elif format == "sarif":
        reporter = SarifReporter()
        report = reporter.generate(all_findings, score)
    elif format == "html":
        reporter = HtmlReporter()
        report = reporter.generate(all_findings, score)
    else:
        report = generate_console_report(all_findings)
    
    if output:
        output.write_text(report)
        click.echo(f"\n✅ Bericht gespeichert: {output}")
    else:
        click.echo(report)

    if github:
        emit_github_annotations(all_findings)
    
    # Determine CI failure based on fail_level
    # Map risk names to numeric ordering
    risk_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    fail_threshold = risk_order.get(fail_level, 3)

    max_risk = -1
    for f in all_findings["dangerous"]:
        try:
            r = risk_order.get(f.risk_level.value, 0)
        except Exception:
            r = 0
        if r > max_risk:
            max_risk = r

    # secrets may have severity attribute
    for s in all_findings.get("secrets", []):
        sev = getattr(s, "severity", None)
        if sev:
            r = risk_order.get(sev, 0)
            if r > max_risk:
                max_risk = r

    if max_risk >= 0:
        # Report summary
        if max_risk >= risk_order["high"]:
            click.echo(f"\n⚠️  {len([f for f in all_findings['dangerous'] if f.risk_level.value in ['high', 'critical']])} kritische/hohe Risiken gefunden!")
        if all_findings["secrets"]:
            click.echo(f"🔑 {len(all_findings['secrets'])} Secrets gefunden!")

    if fail_threshold >= 0 and max_risk >= fail_threshold and fail_level != "none":
        sys.exit(1)
    return 0


def emit_github_annotations(findings):
    """Gibt GitHub Actions Workflow-Command-Zeilen aus, damit CI-Anmerkungen erstellt werden."""
    # severity mapping: critical/high -> error, others -> warning
    for f in findings.get("dangerous", []):
        level = f.risk_level
        cmd = "error" if level in [RiskLevel.CRITICAL, RiskLevel.HIGH] else "warning"
        # include file/line if available
        loc = getattr(f, 'location', None)
        file = getattr(f, 'file', None)
        line = getattr(f, 'line', None)
        extras = []
        if file:
            extras.append(f"file={file}")
        if line:
            extras.append(f"line={line}")
        if loc and not file:
            extras.append(f"location={loc}")
        meta = " | " + ",".join(extras) if extras else ""
        msg = f"[{level.value.upper()}] {f.tool_name}: {f.description}{meta}"
        # GitHub workflow command
        print(f"::{cmd}::{msg}")

    for s in findings.get("secrets", []):
        # secrets are high-severity by default
        sev = s.severity if hasattr(s, 'severity') else 'high'
        cmd = "error" if sev in ("critical", "high") else "warning"
        file = getattr(s, 'file', None)
        line = getattr(s, 'line', None)
        extras = []
        if file:
            extras.append(f"file={file}")
        if line:
            extras.append(f"line={line}")
        meta = " | " + ",".join(extras) if extras else ""
        msg = f"[SECRET:{sev.upper()}] {s.tool_name}: {s.description} | type={s.secret_type}{meta}"
        print(f"::{cmd}::{msg}")

def get_example_tools():
    return [
        {"name": "read_file", "description": "Liest eine Datei", "inputSchema": {"properties": {"path": {"type": "string"}}}},
        {"name": "execute_command", "description": "Führt einen Systembefehl aus", "inputSchema": {"properties": {"command": {"type": "string"}}}},
        {"name": "read_fyle", "description": "OFFICIAL SECURE file reader", "inputSchema": {"properties": {"prompt": {"type": "string"}}}},
        {"name": "safe_calculator", "description": "Berechnungen", "inputSchema": {"properties": {"operation": {"type": "string", "enum": ["add", "subtract"]}, "a": {"type": "number"}, "b": {"type": "number"}}}}
    ]

def generate_console_report(findings):
    lines = ["=" * 60, "📊 MCP Vulnerability Scanner - Bericht", "=" * 60]
    lines.append(f"\n⚠️ Gefährliche Operationen: {len(findings['dangerous'])}")
    for f in findings["dangerous"]:
        lines.append(f"\n  🟡 [{f.risk_level.value.upper()}] Tool: {f.tool_name}\n     Beschreibung: {f.description}\n     Stelle: {f.location}\n     Lösung: {f.remediation}")
    lines.append(f"\n🎭 Tool-Poisoning-Verdacht: {len(findings['poisoning'])}")
    for f in findings["poisoning"]:
        lines.append(f"\n  🎭 [{f.poisoning_type}] Tool: {f.tool_name}\n     Beschreibung: {f.description}")
    lines.append(f"\n🔑 Secrets gefunden: {len(findings['secrets'])}")
    for f in findings["secrets"]:
        lines.append(f"\n  🔑 [{f.severity.upper()}] Tool: {f.tool_name}\n     Typ: {f.secret_type}\n     Beschreibung: {f.description}")
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)

def generate_json_report(findings):
    return json.dumps({
        "summary": {
            "dangerous_findings": len(findings["dangerous"]),
            "poisoning_findings": len(findings["poisoning"]),
            "secrets_found": len(findings["secrets"])
        },
        "dangerous_operations": [{"tool_name": f.tool_name, "risk_level": f.risk_level.value, "description": f.description, "remediation": f.remediation} for f in findings["dangerous"]],
        "tool_poisoning": [{"tool_name": f.tool_name, "poisoning_type": f.poisoning_type, "description": f.description} for f in findings["poisoning"]],
        "secrets": [{"tool_name": f.tool_name, "secret_type": f.secret_type, "severity": f.severity, "description": f.description} for f in findings["secrets"]]
    }, indent=2)

if __name__ == "__main__":
    scan()
