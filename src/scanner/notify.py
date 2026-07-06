import requests
import os

def send_slack_alert(findings, webhook_url=None):
    webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url or not findings:
        return False
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": "🔒 MCP Scanner Findings"}}]
    for f in findings[:5]:
        risk_icon = "🔴" if f.risk_level.value == "critical" else "🟠" if f.risk_level.value == "high" else "🟡"
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{risk_icon} *{f.tool_name}* [{f.risk_level.value}]\n{f.description}"}
        })
    try:
        r = requests.post(webhook_url, json={"blocks": blocks}, timeout=5)
        return r.status_code == 200
    except:
        return False

def send_jira_issue(finding):
    try:
        from jira import JIRA
    except ImportError:
        return False
    server = os.environ.get("JIRA_SERVER")
    email = os.environ.get("JIRA_EMAIL")
    token = os.environ.get("JIRA_TOKEN")
    if not server or not email or not token:
        return False
    try:
        jira = JIRA(server=server, basic_auth=(email, token))
        jira.create_issue(
            project=os.environ.get("JIRA_PROJECT", "SEC"),
            summary=f"MCP Finding: {finding.tool_name} [{finding.risk_level.value}]",
            description=finding.description + "\n\n**Remediation:** " + finding.remediation,
            issuetype={"name": os.environ.get("JIRA_ISSUE_TYPE", "Task")}
        )
        return True
    except:
        return False
