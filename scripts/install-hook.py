#!/usr/bin/env python3
"""
Install pre-commit hook for MCP security scanning.
Usage: python scripts/install-hook.py
"""
import sys
import os
import stat
from pathlib import Path

def install_hook():
    """Install the pre-commit hook in .git/hooks"""
    repo_root = Path(__file__).parent.parent
    hook_src = repo_root / "scripts" / "pre-commit"
    hook_dst = repo_root / ".git" / "hooks" / "pre-commit"
    
    if not hook_src.exists():
        print(f"❌ Hook source not found: {hook_src}")
        return False
    
    if not (repo_root / ".git").exists():
        print(f"❌ Not a git repository: {repo_root}")
        return False
    
    try:
        # Read hook content
        hook_content = hook_src.read_text()
        
        # Write to git hooks directory
        hook_dst.parent.mkdir(parents=True, exist_ok=True)
        hook_dst.write_text(hook_content)
        
        # Make executable
        st = hook_dst.stat()
        hook_dst.chmod(st.st_mode | stat.S_IEXEC | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        
        print(f"✅ Pre-commit hook installed: {hook_dst}")
        print("   The hook will run security scans before each commit")
        print("   Use 'git commit --no-verify' to bypass (not recommended)")
        return True
    
    except Exception as e:
        print(f"❌ Error installing hook: {e}")
        return False

if __name__ == "__main__":
    if not install_hook():
        sys.exit(1)
    sys.exit(0)
