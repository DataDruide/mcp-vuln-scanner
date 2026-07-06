"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const path = __importStar(require("path"));
function activate(context) {
    console.log('MCP Security Scanner aktiviert');
    // Command: Scan current file
    let scanCommand = vscode.commands.registerCommand('mcp-scanner.scan', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('Keine Datei geöffnet');
            return;
        }
        const filePath = editor.document.uri.fsPath;
        await runScanner(filePath);
    });
    // Command: Scan workspace
    let scanWorkspaceCommand = vscode.commands.registerCommand('mcp-scanner.scanWorkspace', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('Kein Workspace geöffnet');
            return;
        }
        const jsonFiles = await vscode.workspace.findFiles('**/tools.json', '**/node_modules/**');
        if (jsonFiles.length === 0) {
            vscode.window.showErrorMessage('Keine tools.json Dateien gefunden');
            return;
        }
        for (const file of jsonFiles) {
            await runScanner(file.fsPath);
        }
    });
    context.subscriptions.push(scanCommand);
    context.subscriptions.push(scanWorkspaceCommand);
}
async function runScanner(filePath) {
    vscode.window.showInformationMessage(`Scanne: ${path.basename(filePath)}`);
    const pythonPath = '/Users/marcelzimmermann/mcp-security-scanner/venv/bin/mcp-scan';
    const args = [filePath, '--format', 'json'];
    cp.execFile(pythonPath, args, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
            vscode.window.showErrorMessage(`Scanner-Fehler: ${error.message}`);
            return;
        }
        try {
            const result = JSON.parse(stdout);
            showResults(result);
        }
        catch (e) {
            vscode.window.showErrorMessage(`JSON-Parse-Fehler: ${e}`);
        }
    });
}
function showResults(result) {
    const findings = result.dangerous_operations || [];
    const poisoning = result.tool_poisoning || [];
    const panel = vscode.window.createWebviewPanel('mcpScannerResults', 'MCP Security Scanner Ergebnisse', vscode.ViewColumn.Beside, { enableScripts: true });
    panel.webview.html = getWebviewContent(findings, poisoning);
}
function getWebviewContent(findings, poisoning) {
    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: system-ui; padding: 20px; }
        .finding { border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; background: #f8f9fa; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #28a745; }
        .tool-name { font-weight: bold; font-size: 1.1em; }
        .remediation { background: #e9ecef; padding: 8px; border-radius: 4px; margin-top: 8px; font-family: monospace; }
        .badge { display: inline-block; padding: 2px 6px; border-radius: 12px; font-size: 0.75em; margin-left: 10px; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; }
    </style>
</head>
<body>
    <h1>🔒 MCP Security Scanner</h1>
    <p>Gefährliche Operationen: ${findings.length} | Tool-Poisoning: ${poisoning.length}</p>
    
    <h2>⚠️ Gefährliche Operationen</h2>
    ${findings.map((f) => `
        <div class="finding ${f.risk_level}">
            <div class="tool-name">${f.tool_name}<span class="badge badge-${f.risk_level}">${f.risk_level.toUpperCase()}</span></div>
            <div>${f.description}</div>
            <div><strong>Ort:</strong> ${f.location}</div>
            <div class="remediation">🔧 ${f.remediation}</div>
        </div>
    `).join('')}
    
    <h2>🎭 Tool-Poisoning</h2>
    ${poisoning.map((p) => `
        <div class="finding">
            <div class="tool-name">${p.tool_name}<span class="badge">Vertrauen: ${Math.round(p.confidence * 100)}%</span></div>
            <div><strong>Typ:</strong> ${p.poisoning_type}</div>
            <div>${p.description}</div>
            ${p.suggested_alternative ? `<div class="remediation">💡 Alternative: ${p.suggested_alternative}</div>` : ''}
        </div>
    `).join('')}
</body>
</html>
    `;
}
function deactivate() { }
//# sourceMappingURL=extension.js.map