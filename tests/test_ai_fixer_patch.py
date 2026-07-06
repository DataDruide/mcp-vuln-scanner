import sys
import os
import json
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner.cli import scan
from src.scanner.ai_fixer import AIFixer


def test_generate_patch():
    fixer = AIFixer()
    orig = {"name":"t","inputSchema":{"properties":{"cmd":{"type":"string"}}}}
    updated = {"name":"t","inputSchema":{"properties":{"cmd":{"type":"string","pattern":"^safe$"}}}}
    patch = fixer.generate_patch(orig, updated)
    assert '+++' in patch or '@@' in patch
    print('✅ Patch generated')


def test_cli_dry_run_and_git_patch(tmp_path):
    runner = CliRunner()
    tools = [{"name":"execute_command","inputSchema":{"properties":{"command":{"type":"string"}}}}]
    p = tmp_path / 'tools.json'
    p.write_text(json.dumps({"tools": tools}))

    # dry-run
    res = runner.invoke(scan, [str(p), '--fix', '--apply', '--dry-run'])
    assert 'Dry-run' in res.output or 'Dry-run' in res.output

    # git-patch
    res2 = runner.invoke(scan, [str(p), '--fix', '--apply', '--git-patch'])
    assert 'Git Patch Output' in res2.output
    assert 'Patch for' in res2.output
    print('✅ CLI dry-run and git-patch outputs present')
