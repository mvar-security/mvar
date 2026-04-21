"""
MVAR Framework Adapters — 1.5.0 API
====================================

Framework-specific integrations for Claude Code, CrewAI, LangChain, AutoGen, and MCP.

Note: The legacy mvar_adapters package is deprecated and will be removed in 2.0.0.
      Please migrate to this new API.
"""

# Claude Code adapter
from .claude_code import install_hook, uninstall_hook, verify_installation, test_hook

# TODO: Import other adapters when implemented
# from .crewai import wrap_crewai_tool
# from .langchain import MVARCallbackHandler
# from .autogen import wrap_autogen_agent
# from .mcp import wrap_mcp_tool

__all__ = [
    "install_hook",
    "uninstall_hook",
    "verify_installation",
    "test_hook",
]
