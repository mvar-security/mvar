"""First-party MVAR adapter wrappers for common agent ecosystems."""

from .base import MVARExecutionAdapter
from .langchain import MVARLangChainAdapter
from .openai import MVAROpenAIAdapter
from .mcp import MVARMCPAdapter
from .claude import MVARClaudeToolAdapter
from .autogen import MVARAutoGenAdapter
from .crewai import MVARCrewAIAdapter
from .openclaw import MVAROpenClawAdapter
from .google_adk import MVARGoogleADKAdapter
from .openai_agents import MVAROpenAIAgentsAdapter

__all__ = [
    "MVARExecutionAdapter",
    "MVARLangChainAdapter",
    "MVAROpenAIAdapter",
    "MVARMCPAdapter",
    "MVARClaudeToolAdapter",
    "MVARAutoGenAdapter",
    "MVARCrewAIAdapter",
    "MVAROpenClawAdapter",
    "MVARGoogleADKAdapter",
    "MVAROpenAIAgentsAdapter",
]
