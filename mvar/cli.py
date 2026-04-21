#!/usr/bin/env python3
"""
MVAR CLI — Command-line interface for mvar-security 1.5.2
==========================================================

Usage:
    mvar init --framework <name>
    mvar policy list
    mvar policy add <rule_file>
    mvar mission-control setup
    mvar info
    mvar --version

Frameworks: claude-code (others deferred to 1.6.0)
"""

import sys
import argparse
from typing import Optional


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="mvar",
        description="MVAR — Information Flow Control for LLM Agent Runtimes",
    )
    parser.add_argument("--version", action="store_true", help="Show version information")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # mvar init --framework <name>
    init_parser = subparsers.add_parser("init", help="Initialize MVAR for a framework")
    init_parser.add_argument(
        "--framework",
        required=True,
        choices=["claude-code"],
        help="Framework to configure (only claude-code currently supported)",
    )

    # mvar policy list/add
    policy_parser = subparsers.add_parser("policy", help="Manage policy rules")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command")

    policy_subparsers.add_parser("list", help="List active policy rules")

    add_parser = policy_subparsers.add_parser("add", help="Add custom policy rules")
    add_parser.add_argument("rule_file", help="Path to YAML or JSON rule file")

    # mvar mission-control setup
    subparsers.add_parser("mission-control", help="Configure Mission Control connection")

    # mvar info
    subparsers.add_parser("info", help="Show system information")

    args = parser.parse_args()

    if args.version:
        print_version()
        return 0

    if args.command == "init":
        return cmd_init(args.framework)
    elif args.command == "policy":
        if args.policy_command == "list":
            return cmd_policy_list()
        elif args.policy_command == "add":
            return cmd_policy_add(args.rule_file)
        else:
            policy_parser.print_help()
            return 1
    elif args.command == "mission-control":
        return cmd_mission_control_setup()
    elif args.command == "info":
        return cmd_info()
    else:
        parser.print_help()
        return 1


def print_version():
    """Print version information."""
    print("=" * 70)
    print("  MVAR — MIRRA Verified Agent Runtime")
    print("  Version 1.5.2")
    print("=" * 70)
    print()
    print("Author: Shawn Cohen")
    print("License: Apache 2.0")
    print("Repository: https://github.com/mvar-security/mvar")
    print()
    print("Fixed in 1.5.1 (Critical Hotfix):")
    print("  - Mission Control import paths (S1501-01, S1501-02)")
    print("  - QSEAL exports and verification (S1501-03, S1501-04)")
    print("  - PostToolUse fail-open contract messaging (S1501-05)")
    print("  - MC_URL configuration support (I1501-01)")
    print("  - Secret leakage in installer/logs (I1501-02)")
    print()
    print("Released in 1.5.0:")
    print("  - Unified CLI with framework-specific installers")
    print("  - Claude Code PostToolUse hook integration")
    print("  - Mission Control adapter with QSEAL signing")
    print("  - Enhanced framework adapters (CrewAI, LangChain, AutoGen, MCP)")
    print()
    print("Use 'mvar --help' for command reference")


def cmd_init(framework: str) -> int:
    """Initialize MVAR for a framework."""
    if framework == "claude-code":
        from mvar.adapters.claude_code import install_hook
        result = install_hook(scope='project', interactive=True)
        return 0 if result['success'] else 1
    else:
        print(f"[mvar init] Initializing {framework}...")
        print(f"ERROR: Not yet implemented for {framework}")
        return 1


def cmd_policy_list() -> int:
    """List active policy rules."""
    print("[mvar policy list] Active policy rules:")
    # TODO: Implement policy listing
    print("ERROR: Not yet implemented")
    return 1


def cmd_policy_add(rule_file: str) -> int:
    """Add custom policy rules from file."""
    print(f"[mvar policy add] Loading rules from {rule_file}...")
    # TODO: Implement policy rule loading
    print("ERROR: Not yet implemented")
    return 1


def cmd_mission_control_setup() -> int:
    """Configure Mission Control connection."""
    print("[mvar mission-control] Setting up Mission Control connection...")
    # TODO: Implement Mission Control setup wizard
    print("ERROR: Not yet implemented")
    return 1


def cmd_info() -> int:
    """Show system information (legacy compatibility)."""
    # Preserve the old 'mvar' command behavior
    print_version()
    print()
    print("Python: >=3.10")
    print()
    print("Cryptographic Signing:")
    print("  Algorithm: ed25519")
    print("  Hash: sha256")
    print()
    print("Architecture:")
    print("  - Provenance taint tracking (IFC)")
    print("  - Capability runtime (deny-by-default)")
    print("  - Sink policy engine (deterministic)")
    print("  - QSEAL audit trail")
    print()
    print("Use 'mvar-doctor' for strict runtime diagnostics.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
