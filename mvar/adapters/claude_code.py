#!/usr/bin/env python3
"""
MVAR Claude Code Adapter — PostToolUse Hook Installer
======================================================

Installs the MVAR governor hook for Claude Code's PostToolUse event.

Usage:
    from mvar.adapters.claude_code import install_hook

    result = install_hook(
        scope='project',
        mc_url='http://localhost:3000',
        mc_api_key='your_key',
        qseal_secret=None  # Auto-generated if not provided
    )

    if result['success']:
        print(f"Installed to {result['hook_path']}")
        print(f"Next steps: {result['next_steps']}")

Or via CLI:
    mvar init --framework claude-code
"""

import json
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Dict, Any


def install_hook(
    scope: str = 'project',
    mc_url: Optional[str] = None,
    mc_api_key: Optional[str] = None,
    qseal_secret: Optional[str] = None,
    interactive: bool = True,
) -> Dict[str, Any]:
    """
    Install MVAR governor hook for Claude Code.

    Args:
        scope: 'project' (local .claude/) or 'user' (global ~/.claude/)
        mc_url: Mission Control URL (default: http://localhost:3000)
        mc_api_key: Mission Control API key (prompts if None and interactive=True)
        qseal_secret: QSEAL signing secret (auto-generated if None)
        interactive: If True, prompt for missing values

    Returns:
        Dict with installation results:
        {
            'success': bool,
            'scope': str,
            'hook_path': Path,
            'settings_path': Path,
            'env_path': Path,
            'qseal_secret': str,
            'mc_api_key': str,
            'mc_url': str,
            'next_steps': str,
            'errors': List[str]
        }
    """
    errors = []

    # Determine paths based on scope
    if scope == 'project':
        hooks_dir = Path.cwd() / '.claude' / 'hooks'
        settings_file = Path.cwd() / '.claude' / 'settings.local.json'
        env_file = Path.cwd() / '.mvar.env'
        gitignore_file = Path.cwd() / '.gitignore'
    elif scope == 'user':
        hooks_dir = Path.home() / '.claude' / 'hooks'
        settings_file = Path.home() / '.claude' / 'settings.json'
        env_file = Path.home() / '.mvar' / 'env'
        gitignore_file = None  # Don't modify global gitignore
    else:
        return {
            'success': False,
            'errors': [f"Invalid scope '{scope}'. Must be 'project' or 'user'."]
        }

    print(f"Installing MVAR governor hook (scope: {scope})...")
    print()

    # Check for Claude Code CLI
    _check_claude_cli()
    print()

    # Step 1: Create hooks directory
    hooks_dir.mkdir(parents=True, exist_ok=True)
    if scope == 'user':
        env_file.parent.mkdir(parents=True, exist_ok=True)

    # Step 2: Copy governor_hook.py from package
    source_hook = Path(__file__).parent.parent / 'hooks' / 'governor_hook.py'
    target_hook = hooks_dir / 'mvar_governor_hook.py'

    if not source_hook.exists():
        errors.append(f"Source hook not found: {source_hook}")
        return {
            'success': False,
            'errors': errors
        }

    print(f"[1/6] Copying hook script...")
    shutil.copy2(source_hook, target_hook)
    target_hook.chmod(0o755)
    print(f"      ✅ {target_hook}")
    print()

    # Step 3: Update settings.local.json (or settings.json for user scope)
    print(f"[2/6] Updating Claude Code settings...")
    settings = _load_or_create_settings(settings_file)

    if 'hooks' not in settings:
        settings['hooks'] = {}

    hook_config = {
        'command': ['python3', str(target_hook)],
        'description': 'MVAR Execution Governor - Policy enforcement + Mission Control reporting'
    }

    # Check for existing hook
    if 'PostToolUse' in settings['hooks']:
        existing = settings['hooks']['PostToolUse']
        if 'mvar_governor_hook' in str(existing.get('command', '')):
            print(f"      ℹ️  MVAR hook already configured")
        else:
            print(f"      ⚠️  WARNING: PostToolUse hook already exists:")
            print(f"         {existing}")
            if interactive:
                response = input("      Overwrite? [y/N]: ").strip().lower()
                if response == 'y':
                    settings['hooks']['PostToolUse'] = hook_config
                    print(f"      ✅ Overwrote PostToolUse hook")
                else:
                    errors.append("User declined to overwrite existing PostToolUse hook")
                    print(f"      ⏭️  Keeping existing hook")
            else:
                errors.append("PostToolUse hook already exists (non-interactive mode)")
                print(f"      ⏭️  Keeping existing hook (non-interactive)")
    else:
        settings['hooks']['PostToolUse'] = hook_config
        print(f"      ✅ Added PostToolUse hook")

    _save_settings(settings_file, settings)
    print(f"      ✅ Updated {settings_file}")
    print()

    # Step 4: Generate QSEAL_SECRET if not provided
    if qseal_secret is None:
        qseal_secret = secrets.token_urlsafe(32)
        print(f"[3/6] Generated QSEAL_SECRET...")
        print("      ✅ QSEAL_SECRET generated")
    else:
        print(f"[3/6] Using provided QSEAL_SECRET...")
        print("      ✅ QSEAL_SECRET configured")
    print()

    # Step 5: Get Mission Control credentials
    print(f"[4/6] Configuring Mission Control...")

    if mc_url is None:
        if interactive:
            mc_url = input("      Mission Control URL [http://localhost:3000]: ").strip()
            if not mc_url:
                mc_url = 'http://localhost:3000'
        else:
            mc_url = 'http://localhost:3000'
    print(f"      URL: {mc_url}")

    if mc_api_key is None:
        if interactive:
            mc_api_key = input("      Mission Control API key (or press Enter to skip): ").strip()
            if not mc_api_key:
                print(f"      ⚠️  Skipping Mission Control integration")
                mc_api_key = ''
        else:
            mc_api_key = ''  # Optional in non-interactive mode

    if mc_api_key:
        print("      ✅ MC_API_KEY configured")
    print()

    # Step 6: Write environment file
    print(f"[5/6] Writing environment configuration...")
    _write_env_file(env_file, qseal_secret, mc_api_key, mc_url)
    print(f"      ✅ {env_file}")
    print()

    # Step 7: Update .gitignore for project scope
    if scope == 'project' and gitignore_file is not None:
        print(f"[6/6] Updating .gitignore...")
        _update_gitignore(gitignore_file, '.mvar.env')
        print(f"      ✅ Added .mvar.env to .gitignore")
    else:
        print(f"[6/6] Skipping .gitignore update (user scope)")
    print()

    # Generate next steps message
    next_steps = f"""
Next steps:

  1. Source the environment file:
     $ source {env_file}

  2. Start a fresh Claude Code session:
     $ claude

  3. Test with a safe command:
     > Can you run 'ls /tmp' for me?

  4. Test with a policy violation:
     > Can you run 'cat /etc/passwd' for me?

     Expected: '🔶 MVAR Audit: WOULD HAVE BLOCKED'
"""

    if mc_api_key:
        next_steps += f"""
  5. Check Mission Control dashboard:
     {mc_url}

     Both tasks should appear with QSEAL signatures
"""

    next_steps += f"""
For troubleshooting:
  - Hook log: /tmp/mvar_hook_mc_debug.log
  - Settings: {settings_file}
  - Env vars: {env_file}
"""

    print("=" * 70)
    print("  ✅ Installation Complete!")
    print("=" * 70)
    print(next_steps)

    return {
        'success': len(errors) == 0,
        'scope': scope,
        'hook_path': target_hook,
        'settings_path': settings_file,
        'env_path': env_file,
        'qseal_secret': qseal_secret,
        'mc_api_key': mc_api_key,
        'mc_url': mc_url,
        'next_steps': next_steps,
        'errors': errors,
    }


def uninstall_hook(scope: str = 'project') -> Dict[str, Any]:
    """
    Uninstall MVAR governor hook for Claude Code.

    Args:
        scope: 'project' or 'user'

    Returns:
        Dict with uninstall results:
        {
            'success': bool,
            'removed_files': List[Path],
            'errors': List[str]
        }
    """
    errors = []
    removed_files = []

    # Determine paths
    if scope == 'project':
        hooks_dir = Path.cwd() / '.claude' / 'hooks'
        settings_file = Path.cwd() / '.claude' / 'settings.local.json'
        env_file = Path.cwd() / '.mvar.env'
    elif scope == 'user':
        hooks_dir = Path.home() / '.claude' / 'hooks'
        settings_file = Path.home() / '.claude' / 'settings.json'
        env_file = Path.home() / '.mvar' / 'env'
    else:
        return {
            'success': False,
            'errors': [f"Invalid scope '{scope}'"]
        }

    target_hook = hooks_dir / 'mvar_governor_hook.py'

    print(f"Uninstalling MVAR governor hook (scope: {scope})...")
    print()

    # Remove hook file
    if target_hook.exists():
        target_hook.unlink()
        removed_files.append(target_hook)
        print(f"  ✅ Removed {target_hook}")
    else:
        print(f"  ℹ️  Hook file not found: {target_hook}")

    # Remove from settings
    if settings_file.exists():
        settings = _load_or_create_settings(settings_file)
        if 'hooks' in settings and 'PostToolUse' in settings['hooks']:
            hook_cmd = str(settings['hooks']['PostToolUse'].get('command', ''))
            if 'mvar_governor_hook' in hook_cmd:
                del settings['hooks']['PostToolUse']
                _save_settings(settings_file, settings)
                print(f"  ✅ Removed PostToolUse hook from {settings_file}")
            else:
                print(f"  ℹ️  PostToolUse hook not managed by MVAR")
        else:
            print(f"  ℹ️  PostToolUse hook not found in {settings_file}")
    else:
        print(f"  ℹ️  Settings file not found: {settings_file}")

    print()
    print(f"Uninstall complete.")
    print(f"Note: {env_file} was not removed. Delete manually if needed.")

    return {
        'success': len(errors) == 0,
        'removed_files': removed_files,
        'errors': errors,
    }


def verify_installation(scope: str = 'project') -> Dict[str, Any]:
    """
    Verify MVAR hook installation.

    Args:
        scope: 'project' or 'user'

    Returns:
        Dict with verification results:
        {
            'success': bool,
            'checks': {
                'hook_exists': bool,
                'settings_configured': bool,
                'env_file_exists': bool,
                'mission_control_reachable': bool
            },
            'details': Dict[str, str],
            'errors': List[str]
        }
    """
    import os

    errors = []
    checks = {
        'hook_exists': False,
        'settings_configured': False,
        'env_file_exists': False,
        'env_vars_set': False,
        'mission_control_reachable': False,
    }
    details = {}

    # Determine paths
    if scope == 'project':
        hooks_dir = Path.cwd() / '.claude' / 'hooks'
        settings_file = Path.cwd() / '.claude' / 'settings.local.json'
        env_file = Path.cwd() / '.mvar.env'
    elif scope == 'user':
        hooks_dir = Path.home() / '.claude' / 'hooks'
        settings_file = Path.home() / '.claude' / 'settings.json'
        env_file = Path.home() / '.mvar' / 'env'
    else:
        return {
            'success': False,
            'errors': [f"Invalid scope '{scope}'"]
        }

    target_hook = hooks_dir / 'mvar_governor_hook.py'

    print(f"Verifying MVAR installation (scope: {scope})...")
    print()

    # Check 1: Hook script exists
    if target_hook.exists():
        checks['hook_exists'] = True
        details['hook_path'] = str(target_hook)
        print(f"  ✅ Hook script exists: {target_hook}")
    else:
        errors.append(f"Hook script not found: {target_hook}")
        print(f"  ❌ Hook script not found: {target_hook}")

    # Check 2: Settings configured
    if settings_file.exists():
        settings = _load_or_create_settings(settings_file)
        if 'hooks' in settings and 'PostToolUse' in settings['hooks']:
            hook_cmd = str(settings['hooks']['PostToolUse'].get('command', ''))
            if 'mvar_governor_hook' in hook_cmd:
                checks['settings_configured'] = True
                details['settings_path'] = str(settings_file)
                print(f"  ✅ Settings configured: {settings_file}")
            else:
                errors.append("PostToolUse hook exists but not managed by MVAR")
                print(f"  ❌ PostToolUse hook not managed by MVAR")
        else:
            errors.append("PostToolUse hook not found in settings")
            print(f"  ❌ PostToolUse hook not configured")
    else:
        errors.append(f"Settings file not found: {settings_file}")
        print(f"  ❌ Settings file not found: {settings_file}")

    # Check 3: Environment file exists
    if env_file.exists():
        checks['env_file_exists'] = True
        details['env_path'] = str(env_file)
        print(f"  ✅ Environment file exists: {env_file}")
    else:
        errors.append(f"Environment file not found: {env_file}")
        print(f"  ❌ Environment file not found: {env_file}")

    # Check 4: Environment variables set
    qseal_secret = os.getenv('QSEAL_SECRET')
    mc_api_key = os.getenv('MC_API_KEY')

    if qseal_secret:
        checks['env_vars_set'] = True
        print(f"  ✅ QSEAL_SECRET is set")
        details['qseal_secret_set'] = 'yes'
    else:
        errors.append("QSEAL_SECRET not set in environment")
        print(f"  ⚠️  QSEAL_SECRET not set (source {env_file})")

    if mc_api_key:
        print(f"  ✅ MC_API_KEY is set")
        details['mc_api_key_set'] = 'yes'
    else:
        print(f"  ⚠️  MC_API_KEY not set (Mission Control disabled)")

    # Check 5: Mission Control reachable (if API key set)
    if mc_api_key:
        mc_url = os.getenv('MC_URL', 'http://localhost:3000')
        try:
            import httpx
            with httpx.Client(timeout=2.0) as client:
                response = client.get(f"{mc_url}/health", headers={'x-api-key': mc_api_key})
                if response.status_code in (200, 404):  # 404 is OK if /health doesn't exist
                    checks['mission_control_reachable'] = True
                    print(f"  ✅ Mission Control reachable: {mc_url}")
                    details['mc_url'] = mc_url
                else:
                    errors.append(f"Mission Control returned {response.status_code}")
                    print(f"  ⚠️  Mission Control returned {response.status_code}")
        except Exception as e:
            errors.append(f"Mission Control unreachable: {e}")
            print(f"  ⚠️  Mission Control unreachable: {e}")
    else:
        print(f"  ⏭️  Skipping Mission Control check (no API key)")

    print()
    success = all([
        checks['hook_exists'],
        checks['settings_configured'],
        checks['env_file_exists'],
    ])

    if success:
        print("✅ Installation verified successfully!")
    else:
        print("⚠️  Installation incomplete. See errors above.")

    return {
        'success': success,
        'checks': checks,
        'details': details,
        'errors': errors,
    }


def test_hook(command: str = 'echo hello', scope: str = 'project') -> Dict[str, Any]:
    """
    Test the installed hook with a sample command.

    Args:
        command: Bash command to test
        scope: 'project' or 'user'

    Returns:
        Dict with test results:
        {
            'success': bool,
            'command': str,
            'decision': str,  # 'allow', 'block', 'step_up', 'error'
            'output': str,
            'errors': List[str]
        }
    """
    import os

    errors = []

    # Determine hook path
    if scope == 'project':
        target_hook = Path.cwd() / '.claude' / 'hooks' / 'mvar_governor_hook.py'
        env_file = Path.cwd() / '.mvar.env'
    elif scope == 'user':
        target_hook = Path.home() / '.claude' / 'hooks' / 'mvar_governor_hook.py'
        env_file = Path.home() / '.mvar' / 'env'
    else:
        return {
            'success': False,
            'errors': [f"Invalid scope '{scope}'"]
        }

    if not target_hook.exists():
        return {
            'success': False,
            'errors': [f"Hook not found: {target_hook}"]
        }

    print(f"Testing hook with command: {command}")
    print()

    # Construct PostToolUse payload
    test_payload = {
        'tool_name': 'Bash',
        'tool_use_id': 'test_' + secrets.token_hex(4),
        'tool_input': {
            'command': command
        },
        'tool_response': f'(simulated output for: {command})'
    }

    # Load environment from .mvar.env
    env = os.environ.copy()
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    # Strip 'export ' prefix if present
                    if line.startswith('export '):
                        line = line[7:]  # Remove 'export '
                    key, value = line.split('=', 1)
                    env[key.strip()] = value.strip()

    # Run hook
    try:
        result = subprocess.run(
            ['python3', str(target_hook)],
            input=json.dumps(test_payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=5,
        )

        if result.returncode == 0:
            try:
                output = json.loads(result.stdout)
                context = output.get('hookSpecificOutput', {}).get('additionalContext', '')

                # Determine decision from context
                if 'ALLOW' in context:
                    decision = 'allow'
                elif 'WOULD HAVE BLOCKED' in context:
                    decision = 'block'
                elif 'WOULD HAVE REQUIRED STEP-UP' in context:
                    decision = 'step_up'
                else:
                    decision = 'unknown'

                print(f"  ✅ Hook executed successfully")
                print(f"  Decision: {decision}")
                print(f"  Context: {context[:200]}")

                return {
                    'success': True,
                    'command': command,
                    'decision': decision,
                    'output': context,
                    'errors': [],
                }
            except json.JSONDecodeError:
                errors.append(f"Hook returned non-JSON: {result.stdout[:200]}")
                print(f"  ❌ Hook returned non-JSON output")
                return {
                    'success': False,
                    'command': command,
                    'decision': 'error',
                    'output': result.stdout[:200],
                    'errors': errors,
                }
        else:
            errors.append(f"Hook exited with code {result.returncode}")
            print(f"  ❌ Hook failed: {result.stderr[:200]}")
            return {
                'success': False,
                'command': command,
                'decision': 'error',
                'output': result.stderr[:200],
                'errors': errors,
            }

    except subprocess.TimeoutExpired:
        errors.append("Hook timed out (>5s)")
        print(f"  ❌ Hook timed out")
        return {
            'success': False,
            'command': command,
            'decision': 'error',
            'output': '',
            'errors': errors,
        }
    except Exception as e:
        errors.append(str(e))
        print(f"  ❌ Test failed: {e}")
        return {
            'success': False,
            'command': command,
            'decision': 'error',
            'output': '',
            'errors': errors,
        }


# ============================================================================
# Helper Functions
# ============================================================================

def _load_or_create_settings(settings_file: Path) -> Dict[str, Any]:
    """Load existing settings or create new dict."""
    if settings_file.exists():
        try:
            with open(settings_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"      ⚠️  Could not parse {settings_file}, creating backup")
            backup = settings_file.with_suffix('.json.backup')
            shutil.copy2(settings_file, backup)
            return {}
    else:
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        return {}


def _save_settings(settings_file: Path, settings: Dict[str, Any]) -> None:
    """Save settings with pretty formatting."""
    with open(settings_file, 'w') as f:
        json.dump(settings, f, indent=2)
        f.write('\n')


def _write_env_file(env_file: Path, qseal_secret: str, mc_api_key: str, mc_url: str) -> None:
    """Write environment configuration file."""
    lines = [
        "# MVAR Security environment variables\n",
        "# Generated by: mvar init --framework claude-code\n",
        "# Load with: source .mvar.env\n",
        "# DO NOT COMMIT THIS FILE\n",
        "\n",
        f"export QSEAL_SECRET={qseal_secret}\n",
    ]

    if mc_api_key:
        lines.append(f"export MC_API_KEY={mc_api_key}\n")

    lines.append(f"export MC_URL={mc_url}\n")

    with open(env_file, 'w') as f:
        f.writelines(lines)

    env_file.chmod(0o600)  # Readable only by owner


def _update_gitignore(gitignore_file: Path, pattern: str) -> None:
    """Add pattern to .gitignore if not already present."""
    if gitignore_file.exists():
        with open(gitignore_file, 'r') as f:
            content = f.read()

        if pattern not in content:
            with open(gitignore_file, 'a') as f:
                if not content.endswith('\n'):
                    f.write('\n')
                f.write(f"\n# MVAR environment file\n{pattern}\n")
    else:
        with open(gitignore_file, 'w') as f:
            f.write(f"# MVAR environment file\n{pattern}\n")


def _check_claude_cli() -> None:
    """Check if Claude Code CLI is installed and warn if not found."""
    import shutil as sh

    claude_bin = sh.which('claude')

    if claude_bin:
        print(f"  ✅ Claude Code CLI found: {claude_bin}")
    else:
        print(f"  ⚠️  WARNING: Claude Code CLI not found in PATH")
        print(f"      The hook will be installed, but you won't be able to use it")
        print(f"      until you install Claude Code:")
        print(f"")
        print(f"      $ npm install -g @anthropics/claude-code")
        print(f"")
        print(f"      Or follow instructions at: https://docs.claude.com/claude-code")


if __name__ == "__main__":
    # CLI usage for testing
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        result = test_hook(command='echo hello', scope='project')
        sys.exit(0 if result['success'] else 1)
    elif len(sys.argv) > 1 and sys.argv[1] == 'verify':
        result = verify_installation(scope='project')
        sys.exit(0 if result['success'] else 1)
    elif len(sys.argv) > 1 and sys.argv[1] == 'uninstall':
        result = uninstall_hook(scope='project')
        sys.exit(0 if result['success'] else 1)
    else:
        result = install_hook(scope='project', interactive=True)
        sys.exit(0 if result['success'] else 1)
